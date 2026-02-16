#!/usr/bin/env python3
"""
Progress Tracker for Agent OS
Beautiful real-time progress tracking using the rich library.

Features:
- Live updating progress bars
- Nested progress (overall + per-scanner)
- Spinner for operations without known duration
- Color coding (green=done, yellow=in-progress, red=error)
- GitHub Actions compatibility (detects TTY)
- Clean console output
"""

import logging
import sys
import time
from contextlib import contextmanager
from datetime import datetime
from typing import Optional, Union

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskID,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.table import Table
from rich.text import Text

logger = logging.getLogger(__name__)


class ProgressTracker:
    """Track and display progress for security scanning operations

    This class provides beautiful, real-time progress tracking for:
    - File scanning loops
    - Scanner execution (Semgrep, Trivy, TruffleHog, Checkov)
    - LLM API calls
    - Report generation

    It automatically detects if running in a TTY (terminal) or CI environment
    and adjusts output accordingly. In GitHub Actions, it falls back to simple
    logging to avoid cluttering the logs.

    Example:
        tracker = ProgressTracker()

        # Track file scanning
        scan_id = tracker.start_scan("Semgrep", total_files=100)
        for i in range(100):
            tracker.update_progress(scan_id, completed=i+1, message=f"Scanning file {i+1}")
        tracker.complete_scan(scan_id)

        # Track operations without known duration
        with tracker.operation("Generating report"):
            generate_report()
    """

    def __init__(self, enable_rich: Optional[bool] = None):
        """Initialize the progress tracker

        Args:
            enable_rich: Force enable/disable rich output. If None, auto-detects
                        based on TTY and environment variables.
        """
        # Detect if we should use rich progress bars
        if enable_rich is None:
            # Disable in CI environments or if not a TTY
            is_ci = any([
                os.environ.get("CI") == "true",
                os.environ.get("GITHUB_ACTIONS") == "true",
                os.environ.get("GITLAB_CI") == "true",
                os.environ.get("JENKINS_URL"),
                os.environ.get("CIRCLECI") == "true",
            ])
            is_tty = sys.stdout.isatty()
            self.use_rich = is_tty and not is_ci
        else:
            self.use_rich = enable_rich

        self.console = Console() if self.use_rich else None
        self.live: Optional[Live] = None
        self.progress: Optional[Progress] = None
        self.tasks: dict[str, TaskID] = {}
        self.operation_spinners: dict[str, TaskID] = {}
        self.start_time = datetime.now()
        self.stats: dict[str, Union[int, float]] = {
            "files_scanned": 0,
            "scanners_completed": 0,
            "llm_calls": 0,
            "errors": 0,
        }

        # Scanner color mappings
        self.scanner_colors = {
            "semgrep": "cyan",
            "trivy": "blue",
            "trufflehog": "magenta",
            "checkov": "yellow",
            "gitleaks": "green",
            "llm": "bright_magenta",
            "report": "bright_cyan",
        }

        logger.info(f"ProgressTracker initialized (rich_enabled={self.use_rich})")

    def _create_progress(self) -> Progress:
        """Create a Progress instance with custom columns"""
        return Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(complete_style="green", finished_style="bold green"),
            MofNCompleteColumn(),
            TextColumn("•"),
            TimeElapsedColumn(),
            TextColumn("•"),
            TimeRemainingColumn(),
            console=self.console,
            expand=False,
        )

    def _create_operation_progress(self) -> Progress:
        """Create a Progress instance for operations (spinners only)"""
        return Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=self.console,
            expand=False,
        )

    def _create_layout(self) -> Table:
        """Create the layout for displaying multiple progress bars"""
        table = Table.grid(expand=True)
        table.add_row(Panel(self.progress, title="📊 Scanning Progress", border_style="cyan"))
        return table

    def start(self) -> None:
        """Start the progress tracker (initializes live display)"""
        if not self.use_rich:
            logger.info("Starting progress tracking...")
            return

        self.progress = self._create_progress()
        self.live = Live(self.progress, console=self.console, refresh_per_second=4)
        self.live.start()
        logger.debug("Rich progress display started")

    def stop(self) -> None:
        """Stop the progress tracker and display summary"""
        if self.live and self.use_rich:
            self.live.stop()
            self.live = None

        # Print summary
        duration = (datetime.now() - self.start_time).total_seconds()
        if self.use_rich:
            self.console.print("\n[bold green]✓ Progress tracking complete[/bold green]")
            self._print_summary(duration)
        else:
            logger.info(f"Progress tracking complete (duration={duration:.1f}s)")

    def _print_summary(self, duration: float) -> None:
        """Print a summary of tracked operations"""
        summary = Table(title="📊 Summary", show_header=False, box=None)
        summary.add_row("Files scanned:", f"[cyan]{self.stats['files_scanned']}[/cyan]")
        summary.add_row("Scanners completed:", f"[green]{self.stats['scanners_completed']}[/green]")
        summary.add_row("LLM calls:", f"[magenta]{self.stats['llm_calls']}[/magenta]")
        if self.stats['errors'] > 0:
            summary.add_row("Errors:", f"[red]{self.stats['errors']}[/red]")
        summary.add_row("Duration:", f"[yellow]{duration:.1f}s[/yellow]")
        self.console.print(summary)

    def start_scan(
        self,
        scanner_name: str,
        total_files: int,
        description: Optional[str] = None,
    ) -> str:
        """Start tracking a scanner's progress

        Args:
            scanner_name: Name of the scanner (e.g., "Semgrep", "Trivy")
            total_files: Total number of files to scan
            description: Optional custom description

        Returns:
            Task ID for updating progress
        """
        task_id = scanner_name.lower()

        if not self.use_rich:
            logger.info(f"Starting {scanner_name} scan ({total_files} files)...")
            self.tasks[task_id] = task_id  # Just store the name
            return task_id

        if not self.progress:
            self.start()

        color = self.scanner_colors.get(scanner_name.lower(), "white")
        desc = description or f"[{color}]{scanner_name}[/{color}]"

        task = self.progress.add_task(desc, total=total_files)
        self.tasks[task_id] = task

        logger.debug(f"Started tracking {scanner_name} (task_id={task_id}, total={total_files})")
        return task_id

    def update_progress(
        self,
        task_id: str,
        completed: Optional[int] = None,
        advance: int = 1,
        message: Optional[str] = None,
    ) -> None:
        """Update progress for a scanner task

        Args:
            task_id: Task ID returned from start_scan()
            completed: Set absolute completed count (overrides advance)
            advance: Increment completed count by this amount
            message: Optional status message to display
        """
        # Update stats regardless of rich mode
        if completed is not None:
            self.stats["files_scanned"] = completed
        else:
            self.stats["files_scanned"] += advance

        if not self.use_rich:
            if message:
                logger.info(f"[{task_id}] {message}")
            return

        if task_id not in self.tasks or not self.progress:
            logger.warning(f"Unknown task_id: {task_id}")
            return

        task = self.tasks[task_id]

        if completed is not None:
            self.progress.update(task, completed=completed)
        else:
            self.progress.advance(task, advance)

        if message:
            # Update description with message
            current_desc = self.progress.tasks[task].description
            # Extract scanner name from current description
            scanner_name = current_desc.split("[/")[0] + "[/]"
            new_desc = f"{scanner_name} - {message}"
            self.progress.update(task, description=new_desc)

    def complete_scan(
        self,
        task_id: str,
        message: Optional[str] = None,
        error: bool = False,
    ) -> None:
        """Mark a scanner task as complete

        Args:
            task_id: Task ID returned from start_scan()
            message: Optional completion message
            error: Whether the scan ended with an error
        """
        if not self.use_rich:
            status = "ERROR" if error else "COMPLETE"
            msg = message or "scan finished"
            logger.info(f"[{task_id}] {status}: {msg}")
            if not error:
                self.stats["scanners_completed"] += 1
            else:
                self.stats["errors"] += 1
            return

        if task_id not in self.tasks or not self.progress:
            logger.warning(f"Unknown task_id: {task_id}")
            return

        task = self.tasks[task_id]

        # Get current task info
        task_obj = self.progress.tasks[task]
        scanner_name = task_obj.description.split("[/")[0] + "[/]"

        if error:
            self.progress.update(
                task,
                description=f"{scanner_name} - [red]✗ Error: {message or 'failed'}[/red]",
            )
            self.stats["errors"] += 1
        else:
            self.progress.update(
                task,
                completed=task_obj.total,
                description=f"{scanner_name} - [green]✓ {message or 'Complete'}[/green]",
            )
            self.stats["scanners_completed"] += 1

        logger.debug(f"Completed {task_id} (error={error})")

    def start_operation(
        self,
        operation_name: str,
        description: Optional[str] = None,
    ) -> str:
        """Start tracking an operation without known duration

        Args:
            operation_name: Name of the operation (e.g., "LLM Analysis", "Report Generation")
            description: Optional custom description

        Returns:
            Operation ID for completing the operation
        """
        op_id = operation_name.lower().replace(" ", "_")

        # Track LLM calls regardless of rich mode
        if "llm" in op_id.lower():
            self.stats["llm_calls"] += 1

        if not self.use_rich:
            logger.info(f"Starting operation: {operation_name}...")
            self.operation_spinners[op_id] = op_id
            return op_id

        if not self.progress:
            self.start()

        color = self.scanner_colors.get(op_id, "white")
        desc = description or f"[{color}]{operation_name}[/{color}]"

        task = self.progress.add_task(desc, total=None)
        self.operation_spinners[op_id] = task

        logger.debug(f"Started operation {operation_name} (op_id={op_id})")
        return op_id

    def complete_operation(
        self,
        operation_id: str,
        message: Optional[str] = None,
        error: bool = False,
    ) -> None:
        """Complete an operation

        Args:
            operation_id: Operation ID returned from start_operation()
            message: Optional completion message
            error: Whether the operation ended with an error
        """
        if not self.use_rich:
            status = "ERROR" if error else "COMPLETE"
            msg = message or "operation finished"
            logger.info(f"[{operation_id}] {status}: {msg}")
            if error:
                self.stats["errors"] += 1
            return

        if operation_id not in self.operation_spinners or not self.progress:
            logger.warning(f"Unknown operation_id: {operation_id}")
            return

        task = self.operation_spinners[operation_id]
        task_obj = self.progress.tasks[task]
        op_name = task_obj.description.split("[/")[0] + "[/]"

        if error:
            self.progress.update(
                task,
                description=f"{op_name} - [red]✗ Error: {message or 'failed'}[/red]",
            )
            self.stats["errors"] += 1
        else:
            self.progress.update(
                task,
                description=f"{op_name} - [green]✓ {message or 'Complete'}[/green]",
            )

        # Remove the spinner after a brief moment
        self.progress.remove_task(task)
        del self.operation_spinners[operation_id]

        logger.debug(f"Completed operation {operation_id} (error={error})")

    @contextmanager
    def operation(self, operation_name: str, description: Optional[str] = None):
        """Context manager for tracking an operation

        Example:
            with tracker.operation("Generating report"):
                generate_report()

        Args:
            operation_name: Name of the operation
            description: Optional custom description
        """
        op_id = self.start_operation(operation_name, description)
        try:
            yield op_id
            self.complete_operation(op_id, message="Complete")
        except Exception as e:
            self.complete_operation(op_id, message=str(e), error=True)
            raise

    def log_info(self, message: str) -> None:
        """Log an info message (works with or without rich)"""
        if self.use_rich and self.console:
            self.console.print(f"[cyan]ℹ[/cyan] {message}")
        else:
            logger.info(message)

    def log_success(self, message: str) -> None:
        """Log a success message (works with or without rich)"""
        if self.use_rich and self.console:
            self.console.print(f"[green]✓[/green] {message}")
        else:
            logger.info(f"SUCCESS: {message}")

    def log_warning(self, message: str) -> None:
        """Log a warning message (works with or without rich)"""
        if self.use_rich and self.console:
            self.console.print(f"[yellow]⚠[/yellow] {message}")
        else:
            logger.warning(message)

    def log_error(self, message: str) -> None:
        """Log an error message (works with or without rich)"""
        if self.use_rich and self.console:
            self.console.print(f"[red]✗[/red] {message}")
        else:
            logger.error(message)

    def print_header(self, title: str, subtitle: Optional[str] = None) -> None:
        """Print a formatted header

        Args:
            title: Main title text
            subtitle: Optional subtitle text
        """
        if self.use_rich and self.console:
            text = Text(title, style="bold cyan")
            if subtitle:
                text.append(f"\n{subtitle}", style="dim")
            self.console.print(Panel(text, border_style="cyan"))
        else:
            logger.info(f"=== {title} ===")
            if subtitle:
                logger.info(subtitle)

    def get_stats(self) -> dict[str, Union[int, float]]:
        """Get current statistics

        Returns:
            Dictionary of statistics (files_scanned, scanners_completed, etc.)
        """
        duration = (datetime.now() - self.start_time).total_seconds()
        return {
            **self.stats,
            "duration_seconds": duration,
        }


# Import os for environment variable checks
import os


def create_progress_tracker(enable_rich: Optional[bool] = None) -> ProgressTracker:
    """Factory function to create a ProgressTracker instance

    Args:
        enable_rich: Force enable/disable rich output. If None, auto-detects.

    Returns:
        Configured ProgressTracker instance
    """
    return ProgressTracker(enable_rich=enable_rich)


# Example usage
if __name__ == "__main__":
    # Example 1: Basic file scanning progress
    print("Example 1: File Scanning Progress\n")
    tracker = ProgressTracker()
    tracker.start()

    # Simulate Semgrep scan
    semgrep_id = tracker.start_scan("Semgrep", total_files=50)
    for i in range(50):
        time.sleep(0.05)  # Simulate work
        tracker.update_progress(semgrep_id, completed=i+1, message=f"Scanning file {i+1}/50")
    tracker.complete_scan(semgrep_id)

    # Simulate Trivy scan
    trivy_id = tracker.start_scan("Trivy", total_files=30)
    for i in range(30):
        time.sleep(0.05)
        tracker.update_progress(trivy_id, advance=1)
    tracker.complete_scan(trivy_id, message="Found 5 vulnerabilities")

    tracker.stop()

    print("\n" + "="*50 + "\n")

    # Example 2: Operations with context manager
    print("Example 2: Operations with Context Manager\n")
    tracker = ProgressTracker()
    tracker.start()

    with tracker.operation("LLM Analysis"):
        time.sleep(2)  # Simulate LLM call

    with tracker.operation("Report Generation"):
        time.sleep(1)  # Simulate report generation

    tracker.stop()

    print("\n" + "="*50 + "\n")

    # Example 3: Error handling
    print("Example 3: Error Handling\n")
    tracker = ProgressTracker()
    tracker.start()

    scan_id = tracker.start_scan("TruffleHog", total_files=20)
    for i in range(10):
        time.sleep(0.1)
        tracker.update_progress(scan_id, advance=1)

    # Simulate an error
    tracker.complete_scan(scan_id, message="Connection timeout", error=True)

    tracker.stop()

    print("\n" + "="*50 + "\n")

    # Example 4: Mixed progress and operations
    print("Example 4: Mixed Progress and Operations\n")
    tracker = ProgressTracker()
    tracker.print_header("Security Audit", "Analyzing codebase for vulnerabilities")
    tracker.start()

    # Run multiple scanners in sequence
    for scanner, files in [("Semgrep", 40), ("Checkov", 25), ("Gitleaks", 15)]:
        scan_id = tracker.start_scan(scanner, total_files=files)
        for i in range(files):
            time.sleep(0.03)
            tracker.update_progress(scan_id, advance=1)
        tracker.complete_scan(scan_id)

    # LLM analysis
    with tracker.operation("LLM Analysis", "Analyzing findings with AI"):
        time.sleep(1.5)

    # Report generation
    with tracker.operation("Report Generation", "Generating SARIF and JSON reports"):
        time.sleep(1)

    tracker.stop()

    # Show stats
    stats = tracker.get_stats()
    print(f"\nFinal stats: {stats}")

    print("\n" + "="*50 + "\n")

    # Example 5: CI environment simulation (no rich output)
    print("Example 5: CI Environment (Plain Logging)\n")
    tracker = ProgressTracker(enable_rich=False)
    tracker.start()

    scan_id = tracker.start_scan("Semgrep", total_files=10)
    for i in range(10):
        time.sleep(0.1)
        tracker.update_progress(scan_id, completed=i+1)
    tracker.complete_scan(scan_id)

    tracker.stop()
