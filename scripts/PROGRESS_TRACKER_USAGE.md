# Progress Tracker Usage Guide

Beautiful real-time progress tracking for Argus using the `rich` library.

## Installation

```bash
pip install rich>=13.0.0
# or
pip install -r requirements.txt
```

## Features

- **Live updating progress bars** - Real-time visual feedback
- **Nested progress tracking** - Overall + per-scanner progress
- **Spinner animations** - For operations without known duration
- **Color coding** - Green (done), Yellow (in-progress), Red (error)
- **GitHub Actions compatible** - Automatically detects CI and falls back to simple logging
- **Clean console output** - Beautiful, informative UI

## Quick Start

```python
from scripts.progress_tracker import ProgressTracker

# Create tracker
tracker = ProgressTracker()
tracker.start()

# Track file scanning
scan_id = tracker.start_scan("Semgrep", total_files=100)
for i in range(100):
    tracker.update_progress(scan_id, completed=i+1)
tracker.complete_scan(scan_id)

tracker.stop()
```

## Usage Examples

### 1. File Scanning Progress

Track progress when scanning files with security tools:

```python
from scripts.progress_tracker import ProgressTracker

tracker = ProgressTracker()
tracker.start()

# Start Semgrep scan
semgrep_id = tracker.start_scan("Semgrep", total_files=50)
for i, file in enumerate(files):
    scan_file(file)
    tracker.update_progress(
        semgrep_id,
        completed=i+1,
        message=f"Scanning {file.name}"
    )
tracker.complete_scan(semgrep_id, message="Found 3 issues")

tracker.stop()
```

### 2. Multiple Scanners (Sequential)

Track multiple scanners running one after another:

```python
tracker = ProgressTracker()
tracker.print_header("Security Scan", "Running multiple security scanners")
tracker.start()

# Scanner 1: Semgrep
semgrep_id = tracker.start_scan("Semgrep", total_files=100)
for i in range(100):
    # Do work...
    tracker.update_progress(semgrep_id, advance=1)
tracker.complete_scan(semgrep_id)

# Scanner 2: Trivy
trivy_id = tracker.start_scan("Trivy", total_files=50)
for i in range(50):
    # Do work...
    tracker.update_progress(trivy_id, advance=1)
tracker.complete_scan(trivy_id)

# Scanner 3: TruffleHog
trufflehog_id = tracker.start_scan("TruffleHog", total_files=30)
for i in range(30):
    # Do work...
    tracker.update_progress(trufflehog_id, advance=1)
tracker.complete_scan(trufflehog_id)

tracker.stop()
```

### 3. Operations with Context Manager

Track operations without known duration (LLM calls, report generation):

```python
tracker = ProgressTracker()
tracker.start()

# Automatic cleanup with context manager
with tracker.operation("LLM Analysis"):
    response = call_llm_api(prompt)

with tracker.operation("Report Generation"):
    generate_sarif_report()

tracker.stop()
```

### 4. Error Handling

Properly handle and display errors:

```python
tracker = ProgressTracker()
tracker.start()

scan_id = tracker.start_scan("Checkov", total_files=20)
try:
    for i in range(20):
        scan_file(files[i])
        tracker.update_progress(scan_id, advance=1)
    tracker.complete_scan(scan_id)
except Exception as e:
    tracker.complete_scan(scan_id, message=str(e), error=True)

tracker.stop()
```

### 5. Logging Messages

Use built-in logging methods for consistent output:

```python
tracker = ProgressTracker()

tracker.log_info("Starting security audit...")
tracker.log_success("All scanners completed successfully")
tracker.log_warning("Some findings require attention")
tracker.log_error("Critical vulnerability detected")
```

## Integration Points

### Semgrep Scanner Integration

```python
# In scripts/semgrep_scanner.py
from scripts.progress_tracker import ProgressTracker

class SemgrepScanner:
    def __init__(self, config, tracker=None):
        self.tracker = tracker or ProgressTracker()
        # ... existing init code ...

    def scan(self, target_path, output_format="json"):
        # Count files to scan
        files = list(Path(target_path).rglob("*.py"))  # Example

        # Start tracking
        scan_id = self.tracker.start_scan("Semgrep", total_files=len(files))

        results = []
        for i, file in enumerate(files):
            result = self._scan_file(file)
            results.append(result)
            self.tracker.update_progress(
                scan_id,
                completed=i+1,
                message=f"Scanning {file.name}"
            )

        self.tracker.complete_scan(scan_id, message=f"Found {len(results)} issues")
        return results
```

### Orchestrator Integration

```python
# In scripts/orchestrator/main.py
from scripts.progress_tracker import ProgressTracker

class AuditOrchestrator:
    def __init__(self, repo_path, config):
        self.tracker = ProgressTracker()
        # ... existing init code ...

    def run(self):
        self.tracker.print_header("AI Security Audit", f"Repository: {self.repo_path}")
        self.tracker.start()

        try:
            # File selection
            with self.tracker.operation("File Selection"):
                self.select_files()

            # Run scanners
            self.run_semgrep_scan()
            self.run_trivy_scan()
            self.run_trufflehog_scan()

            # LLM analysis
            with self.tracker.operation("LLM Analysis"):
                self.execute_llm_analysis()

            # Generate reports
            with self.tracker.operation("Report Generation"):
                self.generate_reports()

            self.tracker.log_success("Audit complete!")
        finally:
            self.tracker.stop()
```

### LLM Manager Integration

```python
# In scripts/orchestrator/llm_manager.py
from scripts.progress_tracker import ProgressTracker

class LLMManager:
    def __init__(self, tracker=None):
        self.tracker = tracker or ProgressTracker()

    def analyze_findings(self, findings):
        with self.tracker.operation("LLM Analysis", f"Analyzing {len(findings)} findings"):
            responses = []
            for finding in findings:
                response = self.call_llm(finding)
                responses.append(response)
        return responses
```

## CI/CD Integration

The tracker automatically detects CI environments and falls back to simple logging:

```python
# GitHub Actions
tracker = ProgressTracker()  # Auto-detects GITHUB_ACTIONS=true
tracker.start()  # Will use simple logging instead of rich output

# Force enable/disable
tracker = ProgressTracker(enable_rich=False)  # Always use simple logging
tracker = ProgressTracker(enable_rich=True)   # Always use rich output
```

## API Reference

### ProgressTracker

#### `__init__(enable_rich: Optional[bool] = None)`
Initialize the progress tracker. Auto-detects TTY and CI environment.

#### `start() -> None`
Start the progress tracker and initialize live display.

#### `stop() -> None`
Stop the progress tracker and display summary.

#### `start_scan(scanner_name: str, total_files: int, description: Optional[str] = None) -> str`
Start tracking a scanner's progress. Returns task ID.

**Parameters:**
- `scanner_name`: Name of the scanner (e.g., "Semgrep", "Trivy")
- `total_files`: Total number of files to scan
- `description`: Optional custom description

**Returns:** Task ID string for updating progress

#### `update_progress(task_id: str, completed: Optional[int] = None, advance: int = 1, message: Optional[str] = None) -> None`
Update progress for a scanner task.

**Parameters:**
- `task_id`: Task ID from start_scan()
- `completed`: Set absolute completed count (overrides advance)
- `advance`: Increment completed count by this amount
- `message`: Optional status message

#### `complete_scan(task_id: str, message: Optional[str] = None, error: bool = False) -> None`
Mark a scanner task as complete.

**Parameters:**
- `task_id`: Task ID from start_scan()
- `message`: Optional completion message
- `error`: Whether the scan ended with an error

#### `start_operation(operation_name: str, description: Optional[str] = None) -> str`
Start tracking an operation without known duration. Returns operation ID.

#### `complete_operation(operation_id: str, message: Optional[str] = None, error: bool = False) -> None`
Complete an operation.

#### `operation(operation_name: str, description: Optional[str] = None)`
Context manager for tracking an operation.

```python
with tracker.operation("LLM Analysis"):
    # Do work...
    pass
```

#### `log_info(message: str) -> None`
Log an info message.

#### `log_success(message: str) -> None`
Log a success message (green checkmark).

#### `log_warning(message: str) -> None`
Log a warning message (yellow warning).

#### `log_error(message: str) -> None`
Log an error message (red X).

#### `print_header(title: str, subtitle: Optional[str] = None) -> None`
Print a formatted header with optional subtitle.

#### `get_stats() -> Dict[str, Union[int, float]]`
Get current statistics.

**Returns:** Dictionary with:
- `files_scanned`: Number of files scanned
- `scanners_completed`: Number of scanners completed
- `llm_calls`: Number of LLM API calls
- `errors`: Number of errors encountered
- `duration_seconds`: Total duration in seconds

## Color Coding

Built-in color mapping for scanners:
- **Semgrep**: Cyan
- **Trivy**: Blue
- **TruffleHog**: Magenta
- **Checkov**: Yellow
- **Gitleaks**: Green
- **LLM**: Bright Magenta
- **Report**: Bright Cyan

## Best Practices

1. **Always use start/stop**: Ensure `start()` and `stop()` are called
2. **Use context managers**: Prefer `with tracker.operation()` for automatic cleanup
3. **Handle errors**: Always call `complete_scan()` even on errors
4. **Pass tracker to modules**: Pass the tracker instance to sub-modules for unified tracking
5. **Check stats**: Use `get_stats()` to retrieve final statistics

## Example: Full Integration

```python
#!/usr/bin/env python3
from pathlib import Path
from scripts.progress_tracker import ProgressTracker
from scripts.semgrep_scanner import SemgrepScanner
from scripts.trivy_scanner import TrivyScanner

def main():
    # Initialize tracker
    tracker = ProgressTracker()
    tracker.print_header("Argus Security Audit", "Comprehensive security analysis")
    tracker.start()

    repo_path = Path(".")

    try:
        # Phase 1: File Discovery
        with tracker.operation("File Discovery"):
            files = list(repo_path.rglob("*.py"))
            tracker.log_info(f"Found {len(files)} Python files")

        # Phase 2: Static Analysis
        semgrep = SemgrepScanner(tracker=tracker)
        semgrep_results = semgrep.scan(repo_path)

        # Phase 3: Vulnerability Scanning
        trivy = TrivyScanner(tracker=tracker)
        trivy_results = trivy.scan(repo_path)

        # Phase 4: LLM Analysis
        with tracker.operation("LLM Analysis"):
            analysis = analyze_with_llm(semgrep_results + trivy_results)

        # Phase 5: Report Generation
        with tracker.operation("Report Generation"):
            generate_reports(analysis)

        tracker.log_success("Audit completed successfully!")

    except Exception as e:
        tracker.log_error(f"Audit failed: {e}")
        raise
    finally:
        tracker.stop()
        stats = tracker.get_stats()
        print(f"\nFinal Statistics: {stats}")

if __name__ == "__main__":
    main()
```

## Troubleshooting

### Progress bars not showing
- Check if running in a TTY: `sys.stdout.isatty()`
- Check CI environment variables
- Force enable: `ProgressTracker(enable_rich=True)`

### Rich module not found
```bash
pip install rich>=13.0.0
```

### Progress bars garbled in CI
The tracker auto-detects CI and uses simple logging. To force simple logging:
```python
tracker = ProgressTracker(enable_rich=False)
```

## Testing

Run the example script to see all features:

```bash
python3 scripts/progress_tracker.py
```

This will demonstrate:
1. Basic file scanning progress
2. Operations with context manager
3. Error handling
4. Mixed progress and operations
5. CI environment simulation
