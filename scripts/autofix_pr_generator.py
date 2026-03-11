#!/usr/bin/env python3
"""
AutoFix PR Generator for Argus Security

Generates merge-ready pull requests from remediation suggestions and orchestrates
a closed-loop find-fix-verify cycle. Integrates with the remediation engine to
automatically create git branches, apply code fixes, and produce PR metadata.

Features:
- Git branch creation and fix application (diff or full-file replacement)
- Descriptive commit messages with vulnerability context
- Formatted PR body generation with vulnerability details
- Closed-loop orchestration: find -> fix -> verify -> PR
- Confidence-based filtering for safe auto-fix deployment
- Batch processing with aggregated results

Usage:
    from autofix_pr_generator import AutoFixPRGenerator, ClosedLoopOrchestrator

    # Generate a single fix PR
    generator = AutoFixPRGenerator(project_path="/path/to/repo")
    fix_pr = generator.create_fix_pr(suggestion)

    # Run the full closed-loop
    orchestrator = ClosedLoopOrchestrator(project_path="/path/to/repo")
    result = orchestrator.run_loop(findings)
"""

from __future__ import annotations

import logging
import os
import subprocess
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path

from utils.io import validate_path_safe

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class FixBranch:
    """Result of creating a git branch and applying a fix.

    Attributes:
        branch_name: Name of the created git branch.
        finding_id: Unique identifier of the finding being fixed.
        vulnerability_type: Category of vulnerability (e.g. "sql_injection").
        file_path: Path to the file that was modified.
        commit_sha: SHA of the commit containing the fix, or None on failure.
        success: Whether the branch was created and fix committed.
        error: Error message if the operation failed.
    """

    branch_name: str
    finding_id: str
    vulnerability_type: str
    file_path: str
    commit_sha: str | None
    success: bool
    error: str | None = None


@dataclass
class FixPR:
    """Metadata for a generated pull request.

    Attributes:
        branch_name: Name of the git branch containing the fix.
        finding_id: Unique identifier of the finding being fixed.
        vulnerability_type: Category of vulnerability.
        file_path: Path to the file that was modified.
        title: Suggested PR title.
        body: Formatted PR body in Markdown.
        commit_sha: SHA of the fix commit, or None on failure.
        pushed: Whether the branch was pushed to a remote.
        success: Whether the PR was successfully prepared.
        error: Error message if the operation failed.
    """

    branch_name: str
    finding_id: str
    vulnerability_type: str
    file_path: str
    title: str
    body: str
    commit_sha: str | None
    pushed: bool
    success: bool
    error: str | None = None

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)


@dataclass
class LoopResult:
    """Aggregated results from a closed-loop orchestration run.

    Attributes:
        total_findings: Total number of findings evaluated.
        fixable: Number of findings deemed fixable.
        fixed: List of successfully generated FixPR objects.
        skipped_low_confidence: Finding IDs skipped due to low confidence.
        failed: List of dicts with finding_id and error for failures.
    """

    total_findings: int
    fixable: int
    fixed: list[FixPR] = field(default_factory=list)
    skipped_low_confidence: list[str] = field(default_factory=list)
    failed: list[dict] = field(default_factory=list)

    @property
    def success_rate(self) -> float:
        """Fraction of fixable findings that were successfully fixed."""
        return len(self.fixed) / self.fixable if self.fixable > 0 else 0.0

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        data = {
            "total_findings": self.total_findings,
            "fixable": self.fixable,
            "fixed": [pr.to_dict() for pr in self.fixed],
            "skipped_low_confidence": self.skipped_low_confidence,
            "failed": self.failed,
            "success_rate": self.success_rate,
        }
        return data


# ---------------------------------------------------------------------------
# AutoFixPRGenerator
# ---------------------------------------------------------------------------


class AutoFixPRGenerator:
    """Generates merge-ready PRs from remediation suggestions.

    Creates git branches, applies code fixes (via diff or file replacement),
    commits changes with descriptive messages, and produces formatted PR bodies.
    All git operations are performed via subprocess calls.
    """

    def __init__(self, project_path: str, base_branch: str = "main"):
        """Initialize the PR generator.

        Args:
            project_path: Absolute path to the git repository root.
            base_branch: Name of the base branch to create fix branches from.
        """
        self.project_path = os.path.abspath(project_path)
        self.base_branch = base_branch

    def _run_git(self, *args: str, check: bool = True) -> subprocess.CompletedProcess:
        """Run a git command inside the project directory.

        Args:
            *args: Arguments to pass after ``git``.
            check: Whether to raise on non-zero exit code.

        Returns:
            CompletedProcess instance with captured output.
        """
        cmd = ["git", *args]
        logger.debug("Running: %s", " ".join(cmd))
        result = subprocess.run(
            cmd,
            cwd=self.project_path,
            capture_output=True,
            text=True,
            check=check,
        )
        return result

    # -- Branch + fix application ------------------------------------------------

    def create_fix_branch(self, suggestion: dict) -> FixBranch:
        """Create a git branch with the applied fix and commit it.

        Checks out a new branch from ``base_branch``, applies the fix using
        ``_apply_fix``, stages the changed file, and creates a commit with a
        descriptive message.

        Args:
            suggestion: Dict with keys ``finding_id``, ``vulnerability_type``,
                ``file_path``, and either ``diff`` or ``fixed_code``.

        Returns:
            FixBranch describing the outcome.
        """
        finding_id = suggestion.get("finding_id", "unknown")
        vuln_type = suggestion.get("vulnerability_type", "unknown")
        file_path = suggestion.get("file_path", "")
        short_id = finding_id[:8] if finding_id else "unknown"

        # Sanitise vuln_type for branch name (lowercase, replace non-alnum)
        safe_vuln = vuln_type.lower().replace(" ", "-")
        safe_vuln = "".join(c if c.isalnum() or c == "-" else "-" for c in safe_vuln)
        branch_name = f"argus/fix-{safe_vuln}-{short_id}"

        logger.info(
            "Creating fix branch %s for %s in %s",
            branch_name,
            finding_id,
            file_path,
        )

        try:
            # Ensure we start from the base branch
            self._run_git("checkout", self.base_branch)
            self._run_git("checkout", "-b", branch_name)

            # Apply the fix
            if not self._apply_fix(suggestion):
                error_msg = "Failed to apply fix"
                logger.error(error_msg)
                # Return to base branch on failure
                self._run_git("checkout", self.base_branch, check=False)
                self._run_git("branch", "-D", branch_name, check=False)
                return FixBranch(
                    branch_name=branch_name,
                    finding_id=finding_id,
                    vulnerability_type=vuln_type,
                    file_path=file_path,
                    commit_sha=None,
                    success=False,
                    error=error_msg,
                )

            # Stage and commit
            self._run_git("add", file_path)
            commit_msg = self._generate_commit_message(suggestion)
            self._run_git("commit", "-m", commit_msg)

            # Retrieve commit SHA
            sha_result = self._run_git("rev-parse", "HEAD")
            commit_sha = sha_result.stdout.strip()

            logger.info("Fix committed as %s on branch %s", commit_sha, branch_name)

            return FixBranch(
                branch_name=branch_name,
                finding_id=finding_id,
                vulnerability_type=vuln_type,
                file_path=file_path,
                commit_sha=commit_sha,
                success=True,
            )

        except subprocess.CalledProcessError as exc:
            error_msg = f"Git operation failed: {exc.stderr.strip() or exc.stdout.strip()}"
            logger.error(error_msg)
            # Best-effort cleanup
            self._run_git("checkout", self.base_branch, check=False)
            self._run_git("branch", "-D", branch_name, check=False)
            return FixBranch(
                branch_name=branch_name,
                finding_id=finding_id,
                vulnerability_type=vuln_type,
                file_path=file_path,
                commit_sha=None,
                success=False,
                error=error_msg,
            )
        except Exception as exc:
            error_msg = f"Unexpected error: {exc}"
            logger.exception(error_msg)
            self._run_git("checkout", self.base_branch, check=False)
            self._run_git("branch", "-D", branch_name, check=False)
            return FixBranch(
                branch_name=branch_name,
                finding_id=finding_id,
                vulnerability_type=vuln_type,
                file_path=file_path,
                commit_sha=None,
                success=False,
                error=error_msg,
            )

    def _apply_fix(self, suggestion: dict) -> bool:
        """Apply a fix to the working tree.

        If ``suggestion['diff']`` is present, attempt to apply it via
        ``git apply``. If that fails (or no diff is provided) and
        ``suggestion['fixed_code']`` exists, overwrite the target file section.

        Args:
            suggestion: Dict with ``file_path`` and either ``diff`` or
                ``fixed_code`` (and optionally ``original_code``).

        Returns:
            True if the fix was successfully applied, False otherwise.
        """
        file_path = suggestion.get("file_path", "")
        diff_text = suggestion.get("diff", "")
        fixed_code = suggestion.get("fixed_code", "")
        original_code = suggestion.get("original_code", "")

        # Validate file_path once for any path-based operation (diff or fixed_code)
        def _validate_file_path() -> str | None:
            if not file_path or not file_path.strip():
                logger.error("Rejected empty file_path in suggestion")
                return None
            base = Path(self.project_path).resolve()
            try:
                normalized = file_path.strip().lstrip("/").replace("\\", "/")
                safe = validate_path_safe(base / normalized, base_dir=base)
                return str(safe)
            except ValueError:
                logger.error("Rejected path outside project: %s", file_path)
                return None

        # Strategy 1: apply unified diff
        if diff_text:
            try:
                with tempfile.NamedTemporaryFile(
                    mode="w",
                    suffix=".patch",
                    delete=False,
                ) as patch_file:
                    patch_file.write(diff_text)
                    patch_path = patch_file.name

                result = self._run_git("apply", patch_path, check=False)
                os.unlink(patch_path)

                if result.returncode == 0:
                    safe_path = _validate_file_path()
                    if safe_path is None:
                        return False
                    self._run_git("add", safe_path, check=False)
                    logger.info("Applied diff patch to %s", file_path)
                    return True

                logger.warning(
                    "git apply failed (rc=%d): %s",
                    result.returncode,
                    result.stderr.strip(),
                )
            except Exception as exc:
                logger.warning("Diff application error: %s", exc)

        # Strategy 2: overwrite file section with fixed_code
        if fixed_code:
            abs_path = _validate_file_path()
            if abs_path is None:
                return False
            try:
                if original_code and os.path.isfile(abs_path):
                    with open(abs_path) as fh:
                        content = fh.read()

                    if original_code in content:
                        content = content.replace(original_code, fixed_code, 1)
                        with open(abs_path, "w") as fh:
                            fh.write(content)
                        logger.info(
                            "Replaced vulnerable code section in %s",
                            file_path,
                        )
                        return True
                    else:
                        logger.warning(
                            "Original code not found in %s, overwriting file",
                            file_path,
                        )

                # Fallback: overwrite entire file content
                Path(abs_path).parent.mkdir(parents=True, exist_ok=True)
                with open(abs_path, "w") as fh:
                    fh.write(fixed_code)
                logger.info("Wrote fixed code to %s", file_path)
                return True

            except Exception as exc:
                logger.error("Failed to write fixed code to %s: %s", file_path, exc)
                return False

        logger.error("No diff or fixed_code provided in suggestion")
        return False

    # -- Commit message ----------------------------------------------------------

    def _generate_commit_message(self, suggestion: dict) -> str:
        """Generate a descriptive commit message for the fix.

        Format::

            fix(<vuln_type>): <short description>

            Finding: <finding_id>
            CWE: <cwe>
            File: <file_path>:<line_number>

            Generated by Argus Security AutoFix

        Args:
            suggestion: Dict with vulnerability metadata.

        Returns:
            Formatted commit message string.
        """
        vuln_type = suggestion.get("vulnerability_type", "unknown")
        finding_id = suggestion.get("finding_id", "unknown")
        cwe = suggestion.get("cwe", suggestion.get("cwe_references", "N/A"))
        file_path = suggestion.get("file_path", "unknown")
        line_number = suggestion.get("line_number", 0)
        explanation = suggestion.get("explanation", "")

        # Build a short description from the explanation
        if explanation:
            # Take first sentence, capped at 72 chars for subject line
            short_desc = explanation.split(".")[0].strip()
            if len(short_desc) > 60:
                short_desc = short_desc[:57] + "..."
        else:
            short_desc = f"resolve {vuln_type} vulnerability"

        # Format CWE if it is a list
        if isinstance(cwe, list):
            cwe = ", ".join(str(c) for c in cwe)

        message = (
            f"fix({vuln_type}): {short_desc}\n"
            f"\n"
            f"Finding: {finding_id}\n"
            f"CWE: {cwe}\n"
            f"File: {file_path}:{line_number}\n"
            f"\n"
            f"Generated by Argus Security AutoFix"
        )
        return message

    # -- PR body -----------------------------------------------------------------

    def generate_pr_body(
        self,
        suggestion: dict,
        regression_test_path: str | None = None,
    ) -> str:
        """Generate a formatted pull request body in Markdown.

        Includes a summary, vulnerability details, explanation of changes,
        diff in a code block, testing recommendations, and a footer.

        Args:
            suggestion: Dict with vulnerability and fix metadata.
            regression_test_path: Optional path to a generated regression test.

        Returns:
            Markdown-formatted PR body string.
        """
        vuln_type = suggestion.get("vulnerability_type", "unknown")
        finding_id = suggestion.get("finding_id", "unknown")
        cwe = suggestion.get("cwe", suggestion.get("cwe_references", "N/A"))
        severity = suggestion.get("severity", suggestion.get("confidence", "unknown"))
        file_path = suggestion.get("file_path", "unknown")
        line_number = suggestion.get("line_number", 0)
        explanation = suggestion.get("explanation", "No explanation provided.")
        diff_text = suggestion.get("diff", "")
        testing_recs = suggestion.get("testing_recommendations", [])

        # Format CWE if it is a list
        if isinstance(cwe, list):
            cwe = ", ".join(str(c) for c in cwe)

        lines = [
            "## Summary",
            "",
            f"Automated security fix for **{vuln_type}** vulnerability detected by Argus Security.",
            "",
            "## Vulnerability Details",
            "",
            "| Field | Value |",
            "|-------|-------|",
            f"| **Type** | {vuln_type} |",
            f"| **CWE** | {cwe} |",
            f"| **Severity** | {severity} |",
            f"| **File** | `{file_path}` |",
            f"| **Line** | {line_number} |",
            f"| **Finding ID** | `{finding_id}` |",
            "",
            "## What Changed",
            "",
            explanation,
            "",
        ]

        if diff_text:
            lines.extend(
                [
                    "## Diff",
                    "",
                    "```diff",
                    diff_text,
                    "```",
                    "",
                ]
            )

        if testing_recs:
            lines.extend(
                [
                    "## Testing Recommendations",
                    "",
                ]
            )
            for rec in testing_recs:
                lines.append(f"- {rec}")
            lines.append("")

        if regression_test_path:
            lines.extend(
                [
                    "## Regression Test",
                    "",
                    f"A regression test has been added at `{regression_test_path}`.",
                    "",
                ]
            )

        lines.extend(
            [
                "---",
                "",
                "*Generated by [Argus Security](https://github.com/devatsecure/Argus-Security) AutoFix*",
            ]
        )

        return "\n".join(lines)

    # -- Orchestration -----------------------------------------------------------

    def create_fix_pr(
        self,
        suggestion: dict,
        push: bool = False,
    ) -> FixPR:
        """Orchestrate branch creation, fix application, and PR metadata.

        Creates a fix branch, applies the fix, commits it, optionally pushes
        to the remote, and returns a FixPR with all metadata needed to open
        a pull request.

        Args:
            suggestion: Dict with vulnerability and fix metadata.
            push: Whether to push the branch to the remote.

        Returns:
            FixPR with branch name, title, body, and commit information.
        """
        finding_id = suggestion.get("finding_id", "unknown")
        vuln_type = suggestion.get("vulnerability_type", "unknown")
        file_path = suggestion.get("file_path", "")

        logger.info("Creating fix PR for finding %s", finding_id)

        # Create branch and apply fix
        fix_branch = self.create_fix_branch(suggestion)

        if not fix_branch.success:
            return FixPR(
                branch_name=fix_branch.branch_name,
                finding_id=finding_id,
                vulnerability_type=vuln_type,
                file_path=file_path,
                title="",
                body="",
                commit_sha=None,
                pushed=False,
                success=False,
                error=fix_branch.error,
            )

        # Generate PR metadata
        title = f"fix({vuln_type}): {finding_id[:8]} in {os.path.basename(file_path)}"
        body = self.generate_pr_body(suggestion)

        # Optionally push
        pushed = False
        if push:
            try:
                self._run_git("push", "-u", "origin", fix_branch.branch_name)
                pushed = True
                logger.info("Pushed branch %s to origin", fix_branch.branch_name)
            except subprocess.CalledProcessError as exc:
                logger.warning(
                    "Failed to push branch %s: %s",
                    fix_branch.branch_name,
                    exc.stderr.strip(),
                )

        return FixPR(
            branch_name=fix_branch.branch_name,
            finding_id=finding_id,
            vulnerability_type=vuln_type,
            file_path=file_path,
            title=title,
            body=body,
            commit_sha=fix_branch.commit_sha,
            pushed=pushed,
            success=True,
        )


# ---------------------------------------------------------------------------
# ClosedLoopOrchestrator
# ---------------------------------------------------------------------------


CONFIDENCE_LEVELS = {"high": 3, "medium": 2, "low": 1}


class ClosedLoopOrchestrator:
    """Orchestrates the full find -> fix -> verify loop.

    Filters findings to those that are auto-fixable, generates fixes via
    the remediation engine, validates confidence thresholds, and creates
    PR branches for each fix.
    """

    def __init__(
        self,
        project_path: str,
        remediation_engine=None,
        regression_tester=None,
        confidence_threshold: str = "high",
    ):
        """Initialize the orchestrator.

        Args:
            project_path: Absolute path to the git repository root.
            remediation_engine: Optional RemediationEngine instance for
                generating fix suggestions. If None, suggestions must be
                pre-populated in findings.
            regression_tester: Optional callable that takes a suggestion dict
                and returns a test file path (str) or None.
            confidence_threshold: Minimum confidence level required for
                auto-fix ("high", "medium", or "low").
        """
        self.project_path = os.path.abspath(project_path)
        self.remediation_engine = remediation_engine
        self.regression_tester = regression_tester
        self.confidence_threshold = confidence_threshold
        self._pr_generator = AutoFixPRGenerator(self.project_path)

    def run_loop(self, findings: list[dict]) -> LoopResult:
        """Run the closed-loop find-fix-verify cycle.

        Filters findings to those that are fixable, generates a fix for each
        via the remediation engine, validates confidence, creates a branch
        and PR metadata, and optionally generates a regression test.

        Args:
            findings: List of finding dicts from the Argus pipeline.

        Returns:
            LoopResult with aggregated statistics and per-finding outcomes.
        """
        total = len(findings)
        fixable_findings = [f for f in findings if self._is_fixable(f)]
        fixable_count = len(fixable_findings)

        logger.info(
            "Closed-loop: %d total findings, %d fixable",
            total,
            fixable_count,
        )

        result = LoopResult(
            total_findings=total,
            fixable=fixable_count,
        )

        for finding in fixable_findings:
            finding_id = finding.get("finding_id", finding.get("id", "unknown"))

            try:
                # Generate fix suggestion via remediation engine
                suggestion = self._generate_suggestion(finding)

                if suggestion is None:
                    result.failed.append(
                        {
                            "finding_id": finding_id,
                            "error": "Remediation engine returned no suggestion",
                        }
                    )
                    continue

                # Check confidence threshold
                if not self._meets_confidence(suggestion):
                    logger.info(
                        "Skipping %s: confidence %s below threshold %s",
                        finding_id,
                        suggestion.get("confidence", "unknown"),
                        self.confidence_threshold,
                    )
                    result.skipped_low_confidence.append(finding_id)
                    continue

                # Generate regression test if tester is available
                regression_test_path = None
                if self.regression_tester is not None:
                    try:
                        regression_test_path = self.regression_tester(suggestion)
                    except Exception as exc:
                        logger.warning(
                            "Regression test generation failed for %s: %s",
                            finding_id,
                            exc,
                        )

                # Create the fix PR
                fix_pr = self._pr_generator.create_fix_pr(suggestion)

                if fix_pr.success:
                    # Update body with regression test info if available
                    if regression_test_path:
                        fix_pr = FixPR(
                            branch_name=fix_pr.branch_name,
                            finding_id=fix_pr.finding_id,
                            vulnerability_type=fix_pr.vulnerability_type,
                            file_path=fix_pr.file_path,
                            title=fix_pr.title,
                            body=self._pr_generator.generate_pr_body(
                                suggestion,
                                regression_test_path=regression_test_path,
                            ),
                            commit_sha=fix_pr.commit_sha,
                            pushed=fix_pr.pushed,
                            success=True,
                        )
                    result.fixed.append(fix_pr)
                    logger.info("Successfully created fix PR for %s", finding_id)
                else:
                    result.failed.append(
                        {
                            "finding_id": finding_id,
                            "error": fix_pr.error or "Unknown error during PR creation",
                        }
                    )

                # Return to base branch for next iteration
                self._pr_generator._run_git(
                    "checkout",
                    self._pr_generator.base_branch,
                    check=False,
                )

            except Exception as exc:
                logger.exception("Closed-loop failed for finding %s", finding_id)
                result.failed.append(
                    {
                        "finding_id": finding_id,
                        "error": str(exc),
                    }
                )
                # Best-effort return to base branch
                self._pr_generator._run_git(
                    "checkout",
                    self._pr_generator.base_branch,
                    check=False,
                )

        logger.info(
            "Closed-loop complete: %d fixed, %d skipped, %d failed (%.0f%% success rate)",
            len(result.fixed),
            len(result.skipped_low_confidence),
            len(result.failed),
            result.success_rate * 100,
        )

        return result

    def _generate_suggestion(self, finding: dict) -> dict | None:
        """Generate a fix suggestion for a finding.

        Uses the remediation engine if available, converting its output to a
        plain dict. Falls back to returning pre-populated suggestion data
        from the finding itself.

        Args:
            finding: Finding dict with vulnerability metadata.

        Returns:
            Suggestion dict with fix details, or None if generation fails.
        """
        if self.remediation_engine is not None:
            try:
                suggestion_obj = self.remediation_engine.suggest_fix(finding)
                # Convert dataclass/object to dict if needed
                if hasattr(suggestion_obj, "to_dict"):
                    return suggestion_obj.to_dict()
                if hasattr(suggestion_obj, "__dataclass_fields__"):
                    return asdict(suggestion_obj)
                if isinstance(suggestion_obj, dict):
                    return suggestion_obj
                return None
            except Exception as exc:
                logger.warning(
                    "Remediation engine failed for %s: %s",
                    finding.get("finding_id", finding.get("id", "unknown")),
                    exc,
                )
                return None

        # No remediation engine: check if finding already has fix data
        if finding.get("fixed_code") or finding.get("diff"):
            return {
                "finding_id": finding.get("finding_id", finding.get("id", "unknown")),
                "vulnerability_type": finding.get("vulnerability_type", finding.get("type", "unknown")),
                "file_path": finding.get("file_path", finding.get("path", "")),
                "line_number": finding.get("line_number", finding.get("line", 0)),
                "fixed_code": finding.get("fixed_code", ""),
                "original_code": finding.get("original_code", finding.get("code_snippet", "")),
                "diff": finding.get("diff", ""),
                "explanation": finding.get("explanation", ""),
                "confidence": finding.get("confidence", "medium"),
                "cwe": finding.get("cwe", finding.get("cwe_references", "N/A")),
                "severity": finding.get("severity", "unknown"),
                "testing_recommendations": finding.get("testing_recommendations", []),
            }

        return None

    def _is_fixable(self, finding: dict) -> bool:
        """Check if a finding has enough context for auto-fix.

        A finding is fixable if it is explicitly marked ``auto_fixable=True``
        or has a critical/high severity with sufficient code context. At a
        minimum the finding must have a ``file_path``, a vulnerability type
        or category, and either code context or a line number.

        Args:
            finding: Finding dict.

        Returns:
            True if the finding can be auto-fixed.
        """
        # Must have a file path
        file_path = finding.get("file_path") or finding.get("path")
        if not file_path:
            return False

        # Must have a vulnerability type or category
        has_type = bool(finding.get("vulnerability_type") or finding.get("type") or finding.get("category"))
        if not has_type:
            return False

        # Must have code context or a line number
        has_context = bool(
            finding.get("code_snippet")
            or finding.get("original_code")
            or finding.get("line_number")
            or finding.get("line")
        )
        if not has_context:
            return False

        # Explicitly marked as auto-fixable
        if finding.get("auto_fixable") is True:
            return True

        # High/critical severity with context qualifies
        severity = finding.get("severity", "").lower()
        return severity in ("critical", "high")

    def _meets_confidence(self, suggestion: dict) -> bool:
        """Check if a suggestion's confidence meets the threshold.

        Compares the suggestion's confidence level against the configured
        threshold using an ordinal ranking: high > medium > low.

        Args:
            suggestion: Fix suggestion dict with a ``confidence`` key.

        Returns:
            True if the confidence meets or exceeds the threshold.
        """
        suggestion_confidence = suggestion.get("confidence", "low").lower()
        suggestion_level = CONFIDENCE_LEVELS.get(suggestion_confidence, 0)
        threshold_level = CONFIDENCE_LEVELS.get(self.confidence_threshold.lower(), 3)
        return suggestion_level >= threshold_level

    def get_summary(self, result: LoopResult) -> str:
        """Generate a human-readable summary of the loop run.

        Args:
            result: LoopResult from a completed run_loop invocation.

        Returns:
            Multi-line summary string.
        """
        lines = [
            "Argus Security AutoFix - Closed-Loop Summary",
            "=" * 46,
            f"Total findings evaluated: {result.total_findings}",
            f"Fixable findings:        {result.fixable}",
            f"Successfully fixed:      {len(result.fixed)}",
            f"Skipped (low confidence): {len(result.skipped_low_confidence)}",
            f"Failed:                  {len(result.failed)}",
            f"Success rate:            {result.success_rate:.1%}",
        ]

        if result.fixed:
            lines.append("")
            lines.append("Fixed PRs:")
            for pr in result.fixed:
                lines.append(f"  - [{pr.branch_name}] {pr.vulnerability_type} in {pr.file_path}")

        if result.skipped_low_confidence:
            lines.append("")
            lines.append("Skipped (low confidence):")
            for fid in result.skipped_low_confidence:
                lines.append(f"  - {fid}")

        if result.failed:
            lines.append("")
            lines.append("Failed:")
            for fail in result.failed:
                lines.append(f"  - {fail['finding_id']}: {fail.get('error', 'unknown')}")

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


if __name__ == "__main__":
    print("AutoFix PR Generator for Argus Security")
    print("Usage: Integrated into pipeline via enable_autofix_pr=True")
    print("  AutoFixPRGenerator(project_path).create_fix_pr(suggestion)")
    print("  ClosedLoopOrchestrator(project_path).run_loop(findings)")
