"""File selection and filtering module for AI audit orchestration.

This module provides file selection, filtering, and prioritization logic
for code analysis, supporting multiple languages and filtering strategies.
"""

import glob
import logging
import os
import subprocess
from pathlib import Path
from typing import Optional

# Configure logging
logger = logging.getLogger(__name__)


class FileSelector:
    """File selection and filtering for codebase analysis.

    This class handles:
    - Discovering files in a repository
    - Filtering by patterns (include/exclude)
    - Filtering by file extension
    - Filtering by file size
    - Getting changed files from git
    - Prioritizing files based on criticality
    """

    # Extended language support for polyglot codebases
    DEFAULT_EXTENSIONS: set[str] = {
        # Web/Frontend
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".vue",
        ".svelte",
        # Backend
        ".py",
        ".java",
        ".go",
        ".rs",
        ".rb",
        ".php",
        ".cs",
        ".scala",
        ".kt",
        # Systems
        ".c",
        ".cpp",
        ".h",
        ".hpp",
        ".swift",
        # Data/Config
        ".sql",
        ".graphql",
        ".proto",
        # Infrastructure
        ".tf",
        ".yaml",
        ".yml",
    }

    # Directories to skip during traversal
    DEFAULT_SKIP_DIRS: set[str] = {
        ".git",
        "node_modules",
        "venv",
        "__pycache__",
        "dist",
        "build",
        ".next",
        "target",
        "vendor",
        ".gradle",
        ".idea",
        ".vscode",
    }

    # Keywords for prioritizing security-sensitive files
    SECURITY_KEYWORDS: list[str] = ["auth", "security", "password", "token", "secret", "crypto"]

    # Keywords for prioritizing API/Controller files
    API_KEYWORDS: list[str] = ["controller", "api", "route", "handler", "endpoint"]

    # Keywords for prioritizing business logic files
    LOGIC_KEYWORDS: list[str] = ["service", "model", "repository", "dao"]

    def __init__(
        self,
        extensions: Optional[set[str]] = None,
        skip_dirs: Optional[set[str]] = None,
        max_file_size: int = 50000,
        max_files: int = 100,
    ):
        """Initialize FileSelector.

        Args:
            extensions: Set of file extensions to include. Defaults to DEFAULT_EXTENSIONS.
            skip_dirs: Set of directories to skip. Defaults to DEFAULT_SKIP_DIRS.
            max_file_size: Maximum file size in bytes to include (default: 50000).
            max_files: Maximum number of files to select (default: 100).
        """
        self.extensions = extensions or self.DEFAULT_EXTENSIONS
        self.skip_dirs = skip_dirs or self.DEFAULT_SKIP_DIRS
        self.max_file_size = max_file_size
        self.max_files = max_files

    def get_changed_files(self) -> list[str]:
        """Get list of changed files in git working directory.

        Retrieves files changed between HEAD^ and HEAD (typically used in PR context).

        Returns:
            List of relative file paths that have changed. Returns empty list on error.
        """
        try:
            result = subprocess.run(
                ["git", "diff", "--name-only", "HEAD^", "HEAD"],
                capture_output=True,
                text=True,
                check=True,
                timeout=30,
            )
            changed_files = [f.strip() for f in result.stdout.split("\n") if f.strip()]
            logger.info(f"Found {len(changed_files)} changed files")
            return changed_files
        except subprocess.TimeoutExpired:
            logger.warning("Git diff timed out after 30 seconds")
            return []
        except subprocess.CalledProcessError as e:
            # Not necessarily an error - might not be in a PR context
            logger.debug(
                f"Git diff failed (stderr: {e.stderr}). "
                "This is normal if not in a PR context."
            )
            return []
        except FileNotFoundError:
            logger.warning("Git not found in PATH. Ensure git is installed.")
            return []
        except Exception as e:
            logger.error(f"Unexpected error getting changed files: {type(e).__name__}: {e}")
            return []

    def matches_glob_patterns(self, file_path: str, patterns: list[str]) -> bool:
        """Check if file matches any glob pattern.

        Args:
            file_path: File path to check
            patterns: List of glob patterns to match against

        Returns:
            True if file matches any pattern, False otherwise
        """
        if not patterns:
            return False

        return any(
            Path(file_path).match(pattern) or glob.fnmatch.fnmatch(file_path, pattern)
            for pattern in patterns
        )

    def should_exclude_file(
        self,
        rel_path: str,
        include_patterns: Optional[list[str]] = None,
        exclude_patterns: Optional[list[str]] = None,
    ) -> bool:
        """Determine if a file should be excluded based on filters.

        Args:
            rel_path: Relative file path
            include_patterns: List of glob patterns to include (whitelist)
            exclude_patterns: List of glob patterns to exclude (blacklist)

        Returns:
            True if file should be excluded, False if it should be included
        """
        # If include patterns are specified, file must match at least one
        if include_patterns and not self.matches_glob_patterns(rel_path, include_patterns):
            return True

        # If exclude patterns are specified, file must not match any
        return bool(exclude_patterns and self.matches_glob_patterns(rel_path, exclude_patterns))

    def calculate_file_priority(
        self, rel_path: str, only_changed: bool = False
    ) -> int:
        """Calculate priority score for a file based on its path and content type.

        Higher priority scores indicate files that should be reviewed first.

        Args:
            rel_path: Relative file path
            only_changed: If True, add priority boost for changed files

        Returns:
            Priority score (higher = more important)
        """
        priority = 0
        path_lower = rel_path.lower()

        # High priority: Security-sensitive files (100 points)
        if any(keyword in path_lower for keyword in self.SECURITY_KEYWORDS):
            priority += 100

        # High priority: API/Controllers (50 points)
        if any(keyword in path_lower for keyword in self.API_KEYWORDS):
            priority += 50

        # Medium priority: Business logic (30 points)
        if any(keyword in path_lower for keyword in self.LOGIC_KEYWORDS):
            priority += 30

        # Changed files get highest priority boost (200 points)
        if only_changed:
            priority += 200

        return priority

    def get_codebase_files(
        self,
        repo_path: str,
        only_changed: bool = False,
        include_patterns: Optional[list[str]] = None,
        exclude_patterns: Optional[list[str]] = None,
    ) -> list[dict[str, any]]:
        """Get relevant codebase files for analysis with prioritization.

        This method walks the repository, filters files based on extension and
        patterns, applies size constraints, and prioritizes files for analysis.

        Args:
            repo_path: Path to repository root
            only_changed: If True, only include files that have changed (requires git)
            include_patterns: List of glob patterns to include (whitelist)
            exclude_patterns: List of glob patterns to exclude (blacklist)

        Returns:
            List of file dictionaries with keys:
                - path: Relative file path
                - content: File content (truncated to 10000 chars)
                - lines: Number of lines in file
                - size: File size in bytes
                - priority: Priority score for ordering
        """
        important_files = []

        # Get changed files if in PR mode
        changed_files = []
        if only_changed:
            changed_files = self.get_changed_files()
            print(f"📝 PR mode: Found {len(changed_files)} changed files")

        file_priorities: list[tuple[int, dict]] = []

        for root, dirs, files in os.walk(repo_path):
            # Skip common directories
            dirs[:] = [d for d in dirs if d not in self.skip_dirs]

            for file in files:
                # Check if file has supported extension
                if not any(file.endswith(ext) for ext in self.extensions):
                    continue

                file_path = Path(root) / file
                rel_path = str(file_path.relative_to(repo_path))

                # Apply filters
                if only_changed and rel_path not in changed_files:
                    continue

                if self.should_exclude_file(rel_path, include_patterns, exclude_patterns):
                    continue

                try:
                    file_size = file_path.stat().st_size
                    if file_size > self.max_file_size:
                        logger.debug(f"Skipping {rel_path} (too large: {file_size} bytes)")
                        print(f"⏭️  Skipping {rel_path} (too large: {file_size} bytes)")
                        continue

                    with open(file_path, encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                        lines = len(content.split("\n"))

                        # Calculate priority
                        priority = self.calculate_file_priority(rel_path, only_changed)

                        file_priorities.append(
                            (
                                priority,
                                {
                                    "path": rel_path,
                                    "content": content[:10000],  # Limit content size
                                    "lines": lines,
                                    "size": file_size,
                                    "priority": priority,
                                },
                            )
                        )

                except Exception as e:
                    logger.warning(f"Could not read {file_path}: {e}")
                    print(f"Warning: Could not read {file_path}: {e}")

        # Sort by priority (descending) and take top N files
        file_priorities.sort(reverse=True, key=lambda x: x[0])
        important_files = [f[1] for f in file_priorities[: self.max_files]]

        total_lines = sum(f["lines"] for f in important_files)

        print(f"✅ Selected {len(important_files)} files ({total_lines} lines)")
        if file_priorities and len(file_priorities) > self.max_files:
            skipped_count = len(file_priorities) - self.max_files
            print(f"⚠️  {skipped_count} files skipped (priority-based selection)")
            logger.info(f"Skipped {skipped_count} files (priority-based selection)")

        return important_files

    def get_files_to_review(
        self,
        repo_path: str,
        config: Optional[dict[str, any]] = None,
    ) -> list[dict[str, any]]:
        """Get files to review based on configuration.

        This is a convenience method that extracts configuration and calls
        get_codebase_files with the appropriate parameters.

        Args:
            repo_path: Path to repository root
            config: Configuration dictionary with optional keys:
                - only_changed: bool - Only include changed files
                - include_paths: str - Comma-separated glob patterns to include
                - exclude_paths: str - Comma-separated glob patterns to exclude
                - max_file_size: int - Maximum file size in bytes
                - max_files: int - Maximum number of files to select

        Returns:
            List of file dictionaries ready for analysis
        """
        if config is None:
            config = {}

        # Update max sizes from config if provided
        if "max_file_size" in config:
            self.max_file_size = int(config["max_file_size"])
        if "max_files" in config:
            self.max_files = int(config["max_files"])

        # Parse configuration
        only_changed = config.get("only_changed", False)
        include_patterns = [
            p.strip() for p in config.get("include_paths", "").split(",") if p.strip()
        ]
        exclude_patterns = [
            p.strip() for p in config.get("exclude_paths", "").split(",") if p.strip()
        ]

        return self.get_codebase_files(
            repo_path,
            only_changed=only_changed,
            include_patterns=include_patterns or None,
            exclude_patterns=exclude_patterns or None,
        )
