#!/usr/bin/env python3
"""
Diff Impact Analyzer for Argus Security

Diff-intelligent scanner scoping that classifies changed files by security
relevance, expands the blast radius to include dependent files, and builds
a focused scan scope for downstream scanners (Semgrep, Trivy, etc.).

Three main components:

  - **DiffClassifier**     : Classifies changed files into security-relevant
                             vs. skippable buckets using pattern matching.
  - **DiffImpactAnalyzer** : Expands changed files to their security-relevant
                             blast radius via reverse dependency lookup.
  - **DiffScopeBuilder**   : Combines classifier + impact analyzer into a
                             scanner-ready scope with Semgrep CLI helpers.

Toggle: ``only_changed=True`` in ``DiffScopeBuilder.build_scope`` to enable
diff-scoped scanning.  When disabled, the full project is scanned.
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: File patterns that are safe to skip during security scanning.
SKIP_PATTERNS: list[str] = [
    r"\.md$",
    r"\.txt$",
    r"\.css$",
    r"\.scss$",
    r"\.svg$",
    r"\.png$",
    r"\.jpg$",
    r"\.gif$",
    r"CHANGELOG",
    r"LICENSE",
    r"\.gitignore",
    r"README",
]

#: File patterns that must always be scanned regardless of other heuristics.
ALWAYS_SCAN_PATTERNS: list[str] = [
    r"auth",
    r"login",
    r"session",
    r"token",
    r"password",
    r"secret",
    r"key",
    r"crypt",
    r"permission",
    r"rbac",
    r"middleware",
    r"guard",
    r"policy",
    r"\.env",
    r"docker",
    r"Dockerfile",
    r"\.tf$",
    r"\.yml$",
    r"\.yaml$",
    r"\.toml$",
    r"requirements",
    r"package\.json",
    r"Gemfile",
    r"go\.mod",
]

#: Keywords in file paths that indicate security-critical modules.
SECURITY_CRITICAL_KEYWORDS: list[str] = [
    "auth",
    "middleware",
    "permissions",
    "crypto",
    "session",
    "token",
    "oauth",
    "rbac",
    "acl",
    "policy",
    "guard",
    "interceptor",
]

#: File extensions to search when performing reverse dependency lookups.
IMPORTABLE_EXTENSIONS: set[str] = {
    ".py",
    ".js",
    ".ts",
    ".jsx",
    ".tsx",
    ".java",
    ".go",
    ".rb",
    ".php",
}

# Pre-compiled regexes for performance
_SKIP_REGEXES: list[re.Pattern[str]] = [re.compile(p, re.IGNORECASE) for p in SKIP_PATTERNS]
_ALWAYS_SCAN_REGEXES: list[re.Pattern[str]] = [re.compile(p, re.IGNORECASE) for p in ALWAYS_SCAN_PATTERNS]

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class DiffClassification:
    """Result of classifying changed files by security relevance."""

    security_relevant: list[str]
    skippable: list[str]
    should_scan: bool
    total_changed: int


@dataclass
class ScanScope:
    """Scanner-ready scope produced by DiffScopeBuilder."""

    files: list[str] = field(default_factory=list)
    is_scoped: bool = False
    original_changed: list[str] = field(default_factory=list)
    expanded_from: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# DiffClassifier
# ---------------------------------------------------------------------------


class DiffClassifier:
    """Classifies changed files by security relevance.

    Files matching ``SKIP_PATTERNS`` are considered safe to skip.  Files
    matching ``ALWAYS_SCAN_PATTERNS`` are always security-relevant.
    Unmatched files default to security-relevant (scan by default).
    """

    def classify(self, changed_files: list[str]) -> DiffClassification:
        """Classify *changed_files* into security-relevant and skippable.

        Args:
            changed_files: List of file paths (relative to project root)
                that were changed in the diff.

        Returns:
            A ``DiffClassification`` with categorised file lists.
        """
        security_relevant: list[str] = []
        skippable: list[str] = []

        for filepath in changed_files:
            # Always-scan wins over skip
            if self._matches_always_scan(filepath):
                security_relevant.append(filepath)
                logger.debug("Always-scan match: %s", filepath)
                continue

            if self._matches_skip(filepath):
                skippable.append(filepath)
                logger.debug("Skip match: %s", filepath)
                continue

            # Default: treat as security-relevant
            security_relevant.append(filepath)
            logger.debug("Default security-relevant: %s", filepath)

        should_scan = len(security_relevant) > 0

        logger.info(
            "Classified %d files: %d security-relevant, %d skippable, should_scan=%s",
            len(changed_files),
            len(security_relevant),
            len(skippable),
            should_scan,
        )

        return DiffClassification(
            security_relevant=security_relevant,
            skippable=skippable,
            should_scan=should_scan,
            total_changed=len(changed_files),
        )

    # -- helpers -------------------------------------------------------------

    @staticmethod
    def _matches_skip(filepath: str) -> bool:
        """Return True if *filepath* matches any skip pattern."""
        return any(rx.search(filepath) for rx in _SKIP_REGEXES)

    @staticmethod
    def _matches_always_scan(filepath: str) -> bool:
        """Return True if *filepath* matches any always-scan pattern."""
        return any(rx.search(filepath) for rx in _ALWAYS_SCAN_REGEXES)


# ---------------------------------------------------------------------------
# DiffImpactAnalyzer
# ---------------------------------------------------------------------------


class DiffImpactAnalyzer:
    """Expands changed files to their security-relevant blast radius.

    When a security-critical file is changed, this class performs a reverse
    dependency lookup to find all project files that import from it.
    """

    def expand_impact(self, changed_files: list[str], project_path: str) -> list[str]:
        """Expand *changed_files* to include their importers.

        For each changed file that is security-critical, find all project
        files that import from it and add them to the result set.

        Args:
            changed_files: Diff-changed file paths (relative to project root).
            project_path: Absolute or relative path to the project root.

        Returns:
            De-duplicated list of additional files discovered via impact
            analysis (does *not* include the original changed files).
        """
        expanded: set[str] = set()

        for filepath in changed_files:
            if not self._is_security_critical(filepath):
                continue

            logger.info("Security-critical file changed: %s — expanding impact", filepath)
            importers = self._find_importers(filepath, project_path, IMPORTABLE_EXTENSIONS)
            for imp in importers:
                if imp not in changed_files:
                    expanded.add(imp)
                    logger.debug("Impact expansion: %s imports %s", imp, filepath)

        logger.info("Impact analysis expanded scope by %d file(s)", len(expanded))
        return sorted(expanded)

    # -- helpers -------------------------------------------------------------

    @staticmethod
    def _is_security_critical(filepath: str) -> bool:
        """Return True if *filepath* contains a security-critical keyword."""
        lower = filepath.lower()
        return any(kw in lower for kw in SECURITY_CRITICAL_KEYWORDS)

    def _find_importers(
        self,
        target_file: str,
        project_path: str,
        extensions: set[str],
    ) -> list[str]:
        """Find project files that import from *target_file*.

        Searches for ``import``, ``from … import``, and ``require(…)``
        statements referencing the module name derived from *target_file*.

        Args:
            target_file: The file whose importers we want to find.
            project_path: Project root directory.
            extensions: Set of file extensions to search.

        Returns:
            List of file paths (relative to *project_path*) that import
            the target module.
        """
        module_name = self._extract_module_name(target_file)
        if not module_name:
            return []

        # Build regex that matches common import styles across languages:
        #   import module_name
        #   from module_name import …
        #   require('module_name')  /  require("module_name")
        #   import "module_name"
        import_pattern = re.compile(
            r"""
            (?:                                    # non-capturing group
                \bimport\s+.*\b{mod}\b             # import X  /  import {{ X }}
              | \bfrom\s+\S*\b{mod}\b\s+import     # from X import …
              | \brequire\(\s*['\"].*{mod}.*['\"]\s*\)  # require('X')
              | \bimport\s+['\"].*{mod}.*['\"]     # import "X"
            )
            """.format(mod=re.escape(module_name)),
            re.VERBOSE,
        )

        importers: list[str] = []

        for dirpath, _dirnames, filenames in os.walk(project_path):
            # Skip hidden directories and common non-source dirs
            rel_dir = os.path.relpath(dirpath, project_path)
            if any(
                part.startswith(".")
                for part in rel_dir.split(os.sep)
                if part != "."
            ):
                continue
            if any(
                skip in rel_dir
                for skip in ("node_modules", "__pycache__", "vendor", ".git")
            ):
                continue

            for filename in filenames:
                _, ext = os.path.splitext(filename)
                if ext not in extensions:
                    continue

                abs_path = os.path.join(dirpath, filename)
                rel_path = os.path.relpath(abs_path, project_path)

                # Don't match the target file itself
                if os.path.normpath(rel_path) == os.path.normpath(target_file):
                    continue

                try:
                    with open(abs_path, encoding="utf-8", errors="ignore") as fh:
                        content = fh.read()
                except OSError:
                    continue

                if import_pattern.search(content):
                    importers.append(rel_path)

        return importers

    @staticmethod
    def _extract_module_name(filepath: str) -> str:
        """Extract the bare module name from a file path.

        Converts e.g. ``src/auth/middleware.py`` to ``middleware``.

        Args:
            filepath: File path (relative or absolute).

        Returns:
            The basename without extension, or empty string if unusable.
        """
        basename = os.path.basename(filepath)
        name, _ = os.path.splitext(basename)
        return name if name else ""


# ---------------------------------------------------------------------------
# DiffScopeBuilder
# ---------------------------------------------------------------------------


class DiffScopeBuilder:
    """Combines classifier + impact analyzer into a scanner-ready scope.

    Typical usage::

        builder = DiffScopeBuilder()
        changed = builder.get_changed_files(project_path)
        scope   = builder.build_scope(project_path, changed, only_changed=True)
        args    = builder.get_semgrep_include_args(scope)
    """

    def __init__(self) -> None:
        self._classifier = DiffClassifier()
        self._analyzer = DiffImpactAnalyzer()

    def build_scope(
        self,
        project_path: str,
        changed_files: list[str] | None = None,
        only_changed: bool = False,
    ) -> ScanScope:
        """Build a scan scope from the project and optional diff info.

        Args:
            project_path: Absolute or relative path to the project root.
            changed_files: List of changed file paths.  If ``None`` or
                *only_changed* is ``False``, the full project is scanned.
            only_changed: When ``True``, restrict scanning to diff-scoped
                files and their blast radius.

        Returns:
            A ``ScanScope`` describing what to scan.
        """
        if not only_changed or changed_files is None:
            logger.info("Full project scan (only_changed=%s)", only_changed)
            return ScanScope(
                files=[],
                is_scoped=False,
                original_changed=changed_files or [],
                expanded_from=[],
                skipped=[],
            )

        # Step 1: Classify
        classification = self._classifier.classify(changed_files)

        if not classification.should_scan:
            logger.info("No security-relevant changes detected — empty scope")
            return ScanScope(
                files=[],
                is_scoped=True,
                original_changed=changed_files,
                expanded_from=[],
                skipped=classification.skippable,
            )

        # Step 2: Expand impact
        expanded = self._analyzer.expand_impact(
            classification.security_relevant, project_path
        )

        # Step 3: Merge into final file list (de-duplicated, sorted)
        all_files = sorted(set(classification.security_relevant) | set(expanded))

        logger.info(
            "Diff-scoped scan: %d files (%d changed + %d expanded, %d skipped)",
            len(all_files),
            len(classification.security_relevant),
            len(expanded),
            len(classification.skippable),
        )

        return ScanScope(
            files=all_files,
            is_scoped=True,
            original_changed=changed_files,
            expanded_from=expanded,
            skipped=classification.skippable,
        )

    @staticmethod
    def get_changed_files(project_path: str) -> list[str]:
        """Detect changed files via ``git diff``.

        Runs ``git diff --name-only HEAD^ HEAD`` inside *project_path*.
        Falls back to an empty list on any error (e.g. shallow clone,
        no previous commit, git not available).

        Args:
            project_path: Path to the git repository root.

        Returns:
            List of changed file paths relative to the repo root.
        """
        try:
            result = subprocess.run(
                ["git", "diff", "--name-only", "HEAD^", "HEAD"],
                cwd=project_path,
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                logger.warning(
                    "git diff returned non-zero (%d): %s",
                    result.returncode,
                    result.stderr.strip(),
                )
                return []

            files = [
                line.strip()
                for line in result.stdout.strip().splitlines()
                if line.strip()
            ]
            logger.info("git diff detected %d changed file(s)", len(files))
            return files

        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
            logger.warning("Failed to get changed files via git: %s", exc)
            return []

    @staticmethod
    def get_semgrep_include_args(scope: ScanScope) -> list[str]:
        """Convert a scope into Semgrep ``--include`` CLI arguments.

        Args:
            scope: A ``ScanScope`` produced by ``build_scope``.

        Returns:
            A flat list like ``["--include", "file1", "--include", "file2"]``.
            Returns an empty list if the scope is not diff-scoped.
        """
        if not scope.is_scoped or not scope.files:
            return []

        args: list[str] = []
        for filepath in scope.files:
            args.append("--include")
            args.append(filepath)
        return args


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    project = sys.argv[1] if len(sys.argv) > 1 else "."
    builder = DiffScopeBuilder()
    changed = builder.get_changed_files(project)
    scope = builder.build_scope(project, changed, only_changed=True)
    print(
        f"Changed: {len(changed)}, "
        f"Scan scope: {len(scope.files)}, "
        f"Skipped: {len(scope.skipped)}"
    )
