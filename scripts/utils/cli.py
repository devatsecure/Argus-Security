#!/usr/bin/env python3
"""
CLI Utilities for Argus
Provides standardized argument parsing and validation for all scripts.

This module eliminates duplicate CLI argument parsing across 10+ scripts
by providing a common argument parser factory with standard arguments.
"""

import argparse
import sys
from pathlib import Path
from typing import List, Optional


class AgentOSArgumentParser(argparse.ArgumentParser):
    """
    Standardized argument parser for Argus scripts

    Provides common arguments used across all scripts and allows
    easy extension with script-specific arguments.

    Example:
        parser = AgentOSArgumentParser(description="My Scanner")
        parser.add_standard_arguments()
        parser.add_scanner_arguments()
        args = parser.parse_args()
    """

    def __init__(self, *args, **kwargs):
        """
        Initialize parser

        Args:
            *args: Positional arguments for argparse.ArgumentParser
            **kwargs: Keyword arguments for argparse.ArgumentParser
        """
        # Set default formatter if not provided
        if 'formatter_class' not in kwargs:
            kwargs['formatter_class'] = argparse.RawDescriptionHelpFormatter

        super().__init__(*args, **kwargs)
        self._standard_args_added = False
        self._scanner_args_added = False
        self._ai_args_added = False

    def add_standard_arguments(self):
        """
        Add common arguments used across all scripts

        Adds:
            --debug: Enable debug logging
            --output-file: Output file path
            --format: Output format (json, sarif, markdown)
            --verbose: Verbose output
        """
        if self._standard_args_added:
            return

        self.add_argument(
            "--debug",
            action="store_true",
            help="Enable debug logging"
        )

        self.add_argument(
            "--output-file",
            "--output",
            "-o",
            type=Path,
            help="Output file path (JSON, SARIF, or Markdown)"
        )

        self.add_argument(
            "--format",
            choices=["json", "sarif", "markdown", "md"],
            default="json",
            help="Output format (default: json)"
        )

        self.add_argument(
            "--verbose",
            "-v",
            action="store_true",
            help="Enable verbose output"
        )

        self._standard_args_added = True

    def add_ai_arguments(self):
        """
        Add AI provider configuration arguments

        Adds:
            --ai-provider: AI provider (anthropic, openai, ollama)
            --api-key: API key for AI provider
            --model: Specific model to use
            --no-ai: Disable AI verification
        """
        if self._ai_args_added:
            return

        ai_group = self.add_argument_group('AI Configuration')

        ai_group.add_argument(
            "--ai-provider",
            choices=["anthropic", "openai", "ollama", "auto"],
            default="auto",
            help="AI provider for intelligent analysis (default: auto)"
        )

        ai_group.add_argument(
            "--api-key",
            help="API key for AI provider (or use ANTHROPIC_API_KEY/OPENAI_API_KEY env var)"
        )

        ai_group.add_argument(
            "--model",
            help="Specific model to use (e.g., claude-3-sonnet-20240229, gpt-4)"
        )

        ai_group.add_argument(
            "--no-ai",
            action="store_true",
            help="Disable AI verification, use heuristics only"
        )

        self._ai_args_added = True

    def add_scanner_arguments(self):
        """
        Add scanner-specific arguments

        Adds:
            --enable-all-scanners: Enable all available scanners
            --scanners: Specific scanners to enable
            --severity: Severity levels to include
            --max-findings: Limit number of findings
        """
        if self._scanner_args_added:
            return

        scanner_group = self.add_argument_group('Scanner Configuration')

        scanner_group.add_argument(
            "--enable-all-scanners",
            action="store_true",
            help="Enable all available scanners"
        )

        scanner_group.add_argument(
            "--scanners",
            nargs="+",
            choices=["semgrep", "trivy", "trufflehog", "gitleaks", "checkov", "nuclei"],
            help="Specific scanners to enable"
        )

        scanner_group.add_argument(
            "--severity",
            nargs="+",
            choices=["critical", "high", "medium", "low", "info"],
            default=["critical", "high", "medium"],
            help="Severity levels to include (default: critical, high, medium)"
        )

        scanner_group.add_argument(
            "--max-findings",
            type=int,
            help="Maximum number of findings to process"
        )

        self._scanner_args_added = True

    def add_input_file_argument(self, required: bool = True, help_text: Optional[str] = None):
        """
        Add input file argument

        Args:
            required: Whether the argument is required (default: True)
            help_text: Custom help text (default: auto-generated)
        """
        if help_text is None:
            help_text = "Input file path (JSON format)"

        self.add_argument(
            "--input-file",
            "--input",
            "-i",
            type=Path,
            required=required,
            help=help_text
        )

    def add_findings_argument(self, required: bool = True):
        """
        Add findings file argument

        Args:
            required: Whether the argument is required (default: True)
        """
        self.add_argument(
            "--findings",
            type=Path,
            required=required,
            help="Path to findings JSON file (normalized format)"
        )

    def add_target_argument(self, required: bool = True, help_text: Optional[str] = None):
        """
        Add target path argument

        Args:
            required: Whether the argument is required (default: True)
            help_text: Custom help text (default: auto-generated)
        """
        if help_text is None:
            help_text = "Target path to scan (file or directory)"

        self.add_argument(
            "target",
            nargs='?' if not required else None,
            help=help_text
        )


def validate_file_exists(file_path: Path) -> Path:
    """
    Validate that a file exists

    Args:
        file_path: Path to validate

    Returns:
        Path object if valid

    Raises:
        argparse.ArgumentTypeError: If file doesn't exist
    """
    if not file_path.exists():
        raise argparse.ArgumentTypeError(f"File not found: {file_path}")
    if not file_path.is_file():
        raise argparse.ArgumentTypeError(f"Not a file: {file_path}")
    return file_path


def validate_directory_exists(dir_path: Path) -> Path:
    """
    Validate that a directory exists

    Args:
        dir_path: Path to validate

    Returns:
        Path object if valid

    Raises:
        argparse.ArgumentTypeError: If directory doesn't exist
    """
    if not dir_path.exists():
        raise argparse.ArgumentTypeError(f"Directory not found: {dir_path}")
    if not dir_path.is_dir():
        raise argparse.ArgumentTypeError(f"Not a directory: {dir_path}")
    return dir_path


def validate_url(url: str) -> str:
    """
    Validate that a string is a valid URL

    Args:
        url: URL string to validate

    Returns:
        URL string if valid

    Raises:
        argparse.ArgumentTypeError: If URL is invalid
    """
    import re

    # Basic URL validation regex
    url_pattern = re.compile(
        r'^https?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain
        r'localhost|'  # localhost
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # IP
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)

    if not url_pattern.match(url):
        raise argparse.ArgumentTypeError(f"Invalid URL: {url}")

    return url


def validate_severity(severity: str) -> str:
    """
    Validate and normalize severity level

    Args:
        severity: Severity string to validate

    Returns:
        Normalized severity string (lowercase)

    Raises:
        argparse.ArgumentTypeError: If severity is invalid
    """
    valid_severities = ["critical", "high", "medium", "low", "info"]
    severity_lower = severity.lower()

    if severity_lower not in valid_severities:
        raise argparse.ArgumentTypeError(
            f"Invalid severity: {severity}. Must be one of: {', '.join(valid_severities)}"
        )

    return severity_lower


def setup_logging(args: argparse.Namespace):
    """
    Configure logging based on parsed arguments

    Args:
        args: Parsed arguments namespace
    """
    import logging

    if hasattr(args, 'debug') and args.debug:
        level = logging.DEBUG
    elif hasattr(args, 'verbose') and args.verbose:
        level = logging.INFO
    else:
        level = logging.WARNING

    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )


def create_example_usage(script_name: str, examples: List[str]) -> str:
    """
    Create formatted example usage section for help text

    Args:
        script_name: Name of the script
        examples: List of example command lines

    Returns:
        Formatted examples section
    """
    lines = ["\nExamples:"]
    for example in examples:
        lines.append(f"  {script_name} {example}")
    return "\n".join(lines)
