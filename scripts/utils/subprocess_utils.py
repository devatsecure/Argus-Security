#!/usr/bin/env python3
"""
Subprocess Utilities for Argus
Safe subprocess execution with proper error handling and logging.

This module provides utilities for running external commands safely,
NEVER using shell=True with user input, and with proper timeout handling.
"""

import logging
import shlex
import subprocess
from pathlib import Path
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)


class SubprocessError(Exception):
    """Custom exception for subprocess failures"""
    pass


def run_command_safe(
    command: List[str],
    cwd: Optional[Path] = None,
    timeout: int = 300,
    check: bool = True,
    capture_output: bool = True,
    env: Optional[dict] = None
) -> subprocess.CompletedProcess:
    """
    Run command safely without shell=True

    SECURITY NOTE: This function NEVER uses shell=True to prevent
    command injection vulnerabilities. All commands must be passed
    as a list of arguments.

    Args:
        command: List of command arguments (NOT string)
        cwd: Working directory (default: current directory)
        timeout: Timeout in seconds (default: 300)
        check: Raise on non-zero exit code (default: True)
        capture_output: Capture stdout/stderr (default: True)
        env: Environment variables (default: inherit from parent)

    Returns:
        CompletedProcess with stdout/stderr

    Raises:
        ValueError: If command is a string instead of list
        subprocess.TimeoutExpired: If command times out
        subprocess.CalledProcessError: If check=True and command fails

    Example:
        # Good: Safe command execution
        result = run_command_safe(["ls", "-la", user_dir])

        # Bad: Don't do this
        # result = subprocess.run(f"ls -la {user_dir}", shell=True)
    """
    # Validate command is a list, not string
    if isinstance(command, str):
        raise ValueError(
            "Command must be list, not string. "
            "Use shlex.split() if needed, but NEVER shell=True with user input. "
            f"Received: {command!r}"
        )

    if not command:
        raise ValueError("Command list cannot be empty")

    # Log command for debugging (sanitize sensitive args)
    sanitized_cmd = _sanitize_command(command)
    logger.debug(f"Running command: {' '.join(sanitized_cmd)}")

    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            timeout=timeout,
            check=check,
            capture_output=capture_output,
            text=True,
            env=env,
            # CRITICAL: Never use shell=True - it's a security vulnerability
            shell=False
        )

        if result.returncode == 0:
            logger.debug(f"Command succeeded: {sanitized_cmd[0]}")
        else:
            logger.warning(
                f"Command exited with code {result.returncode}: {sanitized_cmd[0]}"
            )

        return result

    except subprocess.TimeoutExpired as e:
        logger.error(f"Command timed out after {timeout}s: {sanitized_cmd[0]}")
        raise

    except subprocess.CalledProcessError as e:
        logger.error(
            f"Command failed with exit code {e.returncode}: {sanitized_cmd[0]}"
        )
        if e.stderr:
            logger.error(f"stderr: {e.stderr[:500]}")  # Limit error output
        raise

    except FileNotFoundError as e:
        logger.error(f"Command not found: {command[0]}")
        raise SubprocessError(f"Command not found: {command[0]}") from e


def run_command_with_retry(
    command: List[str],
    max_retries: int = 3,
    retry_delay: float = 1.0,
    **kwargs
) -> subprocess.CompletedProcess:
    """
    Run command with retry logic

    Args:
        command: List of command arguments
        max_retries: Maximum number of retry attempts (default: 3)
        retry_delay: Delay between retries in seconds (default: 1.0)
        **kwargs: Additional arguments for run_command_safe

    Returns:
        CompletedProcess with stdout/stderr

    Raises:
        SubprocessError: If all retries fail
    """
    import time

    last_error = None

    for attempt in range(max_retries):
        try:
            return run_command_safe(command, **kwargs)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            last_error = e
            if attempt < max_retries - 1:
                logger.warning(
                    f"Command failed (attempt {attempt + 1}/{max_retries}), "
                    f"retrying in {retry_delay}s..."
                )
                time.sleep(retry_delay)
            else:
                logger.error(f"Command failed after {max_retries} attempts")

    raise SubprocessError(
        f"Command failed after {max_retries} attempts: {command[0]}"
    ) from last_error


def run_command_streaming(
    command: List[str],
    cwd: Optional[Path] = None,
    timeout: Optional[int] = None,
    callback: Optional[callable] = None
) -> Tuple[int, str, str]:
    """
    Run command with streaming output

    Args:
        command: List of command arguments
        cwd: Working directory
        timeout: Timeout in seconds (None for no timeout)
        callback: Optional callback function called for each line of output

    Returns:
        Tuple of (return_code, stdout, stderr)

    Example:
        def print_line(line):
            print(f">> {line}")

        code, out, err = run_command_streaming(
            ["npm", "install"],
            callback=print_line
        )
    """
    if isinstance(command, str):
        raise ValueError("Command must be list, not string")

    sanitized_cmd = _sanitize_command(command)
    logger.debug(f"Running command (streaming): {' '.join(sanitized_cmd)}")

    stdout_lines = []
    stderr_lines = []

    try:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False  # NEVER use shell=True
        )

        # Read stdout
        if process.stdout:
            for line in iter(process.stdout.readline, ''):
                if not line:
                    break
                line = line.rstrip()
                stdout_lines.append(line)
                if callback:
                    callback(line)

        # Wait for completion
        process.wait(timeout=timeout)

        # Read stderr
        if process.stderr:
            stderr_lines = process.stderr.read().splitlines()

        return process.returncode, '\n'.join(stdout_lines), '\n'.join(stderr_lines)

    except subprocess.TimeoutExpired:
        if process:
            process.kill()
        logger.error(f"Command timed out: {sanitized_cmd[0]}")
        raise


def check_command_exists(command: str) -> bool:
    """
    Check if a command exists in PATH

    Args:
        command: Command name to check (e.g., "git", "npm")

    Returns:
        True if command exists, False otherwise

    Example:
        if check_command_exists("git"):
            print("Git is installed")
    """
    try:
        result = run_command_safe(
            ["which", command],
            check=False,
            capture_output=True
        )
        return result.returncode == 0
    except Exception:
        return False


def get_command_version(command: str, version_flag: str = "--version") -> Optional[str]:
    """
    Get version string for a command

    Args:
        command: Command name (e.g., "git", "npm")
        version_flag: Version flag to use (default: "--version")

    Returns:
        Version string or None if command not found

    Example:
        version = get_command_version("git")
        # Returns: "git version 2.39.0"
    """
    try:
        result = run_command_safe(
            [command, version_flag],
            check=False,
            capture_output=True,
            timeout=5
        )
        if result.returncode == 0:
            return result.stdout.strip()
        return None
    except Exception as e:
        logger.debug(f"Failed to get version for {command}: {e}")
        return None


def _sanitize_command(command: List[str]) -> List[str]:
    """
    Remove sensitive data from command for logging

    Args:
        command: List of command arguments

    Returns:
        Sanitized command list with sensitive values redacted

    Example:
        >>> _sanitize_command(["curl", "-H", "Authorization: Bearer sk_123"])
        ["curl", "-H", "Authorization: Bearer ***REDACTED***"]
    """
    sanitized = []
    skip_next = False

    # Sensitive argument names
    sensitive_flags = {
        "--api-key", "--token", "--password", "--secret",
        "--bearer", "--auth", "--credentials", "-H",
        "--header", "--Authorization"
    }

    # Sensitive patterns in values
    sensitive_patterns = [
        "api_key=", "token=", "password=", "secret=",
        "bearer ", "authorization:", "apikey="
    ]

    for i, arg in enumerate(command):
        if skip_next:
            sanitized.append("***REDACTED***")
            skip_next = False
            continue

        # Check if this is a sensitive flag
        if arg.lower() in [f.lower() for f in sensitive_flags]:
            sanitized.append(arg)
            skip_next = True
            continue

        # Check if argument contains sensitive pattern
        arg_lower = arg.lower()
        contains_sensitive = any(
            pattern.lower() in arg_lower
            for pattern in sensitive_patterns
        )

        if contains_sensitive and "=" in arg:
            # Redact value but keep key (e.g., "api_key=value" -> "api_key=***REDACTED***")
            key = arg.split("=", 1)[0]
            sanitized.append(f"{key}=***REDACTED***")
        else:
            sanitized.append(arg)

    return sanitized


def parse_command_string(command_str: str) -> List[str]:
    """
    Safely parse a command string into argument list

    Uses shlex.split() to properly handle quoted arguments.

    Args:
        command_str: Command string to parse

    Returns:
        List of command arguments

    Example:
        >>> parse_command_string('git commit -m "fix: bug fix"')
        ['git', 'commit', '-m', 'fix: bug fix']

    WARNING: Only use this for trusted input, never for user-supplied commands!
    """
    try:
        return shlex.split(command_str)
    except ValueError as e:
        raise ValueError(f"Failed to parse command string: {e}") from e


def run_git_command(
    args: List[str],
    repo_path: Optional[Path] = None,
    **kwargs
) -> subprocess.CompletedProcess:
    """
    Run a git command safely

    Args:
        args: Git command arguments (without 'git' prefix)
        repo_path: Repository path (default: current directory)
        **kwargs: Additional arguments for run_command_safe

    Returns:
        CompletedProcess with stdout/stderr

    Example:
        result = run_git_command(["status", "--short"])
        result = run_git_command(["log", "-1", "--format=%H"], repo_path=Path("/path/to/repo"))
    """
    command = ["git"] + args
    return run_command_safe(command, cwd=repo_path, **kwargs)
