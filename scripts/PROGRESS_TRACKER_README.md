# Progress Tracker - Beautiful Real-Time Progress Tracking

Beautiful progress bars and real-time progress tracking for Argus using the `rich` library.

## Files Created

1. **scripts/progress_tracker.py** (584 lines)
   - Main ProgressTracker class implementation
   - Full-featured progress tracking with rich library
   - GitHub Actions compatibility (auto-detects CI)
   - Comprehensive examples and test code

2. **scripts/PROGRESS_TRACKER_USAGE.md**
   - Detailed usage guide and API reference
   - Integration examples for each component
   - Best practices and troubleshooting

3. **scripts/PROGRESS_TRACKER_INTEGRATION_EXAMPLE.py**
   - Runnable integration examples
   - Templates for custom scanner integration
   - Error handling patterns
   - CI behavior demonstrations

4. **requirements.txt** (updated)
   - Added: `rich>=13.0.0`

## Quick Start

```bash
# Install dependencies
pip install rich>=13.0.0

# Or install all requirements
pip install -r requirements.txt

# Test the tracker
python3 scripts/progress_tracker.py
```

## Key Features Implemented

### 1. Live Updating Progress Bars
- Real-time progress tracking with visual bars
- Shows: current/total, time elapsed, time remaining
- Auto-refreshes 4 times per second

### 2. Nested Progress Support
- Track overall progress across multiple scanners
- Per-scanner progress tracking
- Multiple operations running simultaneously

### 3. Spinner for Unknown Duration
- Spinner animation for operations without known duration
- Context manager support for automatic cleanup
- Used for: LLM calls, report generation, initialization

### 4. Color Coding
- **Green**: Completed successfully
- **Yellow**: In progress
- **Red**: Errors
- **Scanner-specific colors**:
  - Semgrep: Cyan
  - Trivy: Blue
  - TruffleHog: Magenta
  - Checkov: Yellow
  - Gitleaks: Green
  - LLM: Bright Magenta

### 5. GitHub Actions Compatibility
- Auto-detects CI environments (GitHub Actions, GitLab CI, Jenkins, CircleCI)
- Automatically falls back to simple logging in CI
- Detects TTY availability
- Can be forced on/off with `enable_rich` parameter

### 6. Clean Console Output
- Formatted headers with panels
- Summary statistics after completion
- Structured logging methods (info, success, warning, error)
- No cluttered output in CI logs

## Usage Examples

### Basic File Scanning

```python
from scripts.progress_tracker import ProgressTracker

tracker = ProgressTracker()
tracker.start()

# Track Semgrep scan
scan_id = tracker.start_scan("Semgrep", total_files=100)
for i in range(100):
    tracker.update_progress(scan_id, completed=i+1)
tracker.complete_scan(scan_id)

tracker.stop()
```

### Operations with Context Manager

```python
tracker = ProgressTracker()
tracker.start()

with tracker.operation("LLM Analysis"):
    response = call_llm_api(prompt)

with tracker.operation("Report Generation"):
    generate_sarif_report()

tracker.stop()
```

### Error Handling

```python
tracker = ProgressTracker()
tracker.start()

scan_id = tracker.start_scan("Trivy", total_files=20)
try:
    for i in range(20):
        scan_file(files[i])
        tracker.update_progress(scan_id, advance=1)
    tracker.complete_scan(scan_id)
except Exception as e:
    tracker.complete_scan(scan_id, message=str(e), error=True)

tracker.stop()
```

## Integration Points

The ProgressTracker is designed to integrate with:

### 1. File Scanning Loops
```python
scan_id = tracker.start_scan("Scanner", total_files=len(files))
for i, file in enumerate(files):
    process_file(file)
    tracker.update_progress(scan_id, completed=i+1, message=f"Scanning {file}")
tracker.complete_scan(scan_id)
```

### 2. Scanner Execution
Integration with:
- **Semgrep** (scripts/semgrep_scanner.py)
- **Trivy** (scripts/trivy_scanner.py)
- **TruffleHog** (scripts/normalizer/trufflehog.py)
- **Checkov** (scripts/normalizer/checkov.py)
- **Gitleaks** (scripts/normalizer/gitleaks.py)

### 3. LLM API Calls
```python
with tracker.operation("LLM Analysis", "Analyzing findings"):
    response = llm_client.call(prompt)
```

### 4. Report Generation
```python
with tracker.operation("Report Generation"):
    generate_sarif()
    generate_json()
    generate_markdown()
```

### 5. Orchestrator Module
Integration with scripts/orchestrator/main.py:
```python
class AuditOrchestrator:
    def __init__(self, repo_path, config):
        self.tracker = ProgressTracker()

    def run(self):
        self.tracker.start()
        # ... orchestration logic ...
        self.tracker.stop()
```

## API Reference

### ProgressTracker Class

#### Initialization
- `__init__(enable_rich: Optional[bool] = None)` - Create tracker with auto-detection

#### Lifecycle
- `start()` - Start the progress tracker
- `stop()` - Stop and show summary

#### File Scanning
- `start_scan(scanner_name, total_files, description)` - Start tracking a scanner
- `update_progress(task_id, completed, advance, message)` - Update progress
- `complete_scan(task_id, message, error)` - Mark scan complete

#### Operations
- `start_operation(operation_name, description)` - Start an operation
- `complete_operation(operation_id, message, error)` - Complete an operation
- `operation(operation_name, description)` - Context manager for operations

#### Logging
- `log_info(message)` - Log info message
- `log_success(message)` - Log success message with checkmark
- `log_warning(message)` - Log warning message
- `log_error(message)` - Log error message with X

#### Utilities
- `print_header(title, subtitle)` - Print formatted header
- `get_stats()` - Get statistics dictionary

## Type Hints and Docstrings

All methods include:
- **Type hints** for all parameters and return values
- **Comprehensive docstrings** with:
  - Description of functionality
  - Args section with parameter descriptions
  - Returns section
  - Examples where applicable

Example:
```python
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
```

## GitHub Actions Compatibility

The tracker automatically detects CI environments:

```python
# Auto-detection
tracker = ProgressTracker()  # Detects GITHUB_ACTIONS=true

# Force simple logging in CI
tracker = ProgressTracker(enable_rich=False)

# Force rich output (testing)
tracker = ProgressTracker(enable_rich=True)
```

Detects:
- `CI=true`
- `GITHUB_ACTIONS=true`
- `GITLAB_CI=true`
- `JENKINS_URL` (present)
- `CIRCLECI=true`

## Statistics Tracking

Automatically tracks:
- Files scanned
- Scanners completed
- LLM calls made
- Errors encountered
- Duration (seconds)

Retrieve with:
```python
stats = tracker.get_stats()
print(f"Files scanned: {stats['files_scanned']}")
print(f"Duration: {stats['duration_seconds']:.1f}s")
```

## Testing

Run the built-in examples:

```bash
# Run all examples (requires rich installed)
python3 scripts/progress_tracker.py

# Run integration examples
python3 scripts/PROGRESS_TRACKER_INTEGRATION_EXAMPLE.py
```

Examples demonstrate:
1. Basic file scanning progress
2. Operations with context manager
3. Error handling
4. Mixed progress and operations
5. CI environment simulation (plain logging)

## Next Steps

### 1. Install Rich
```bash
pip install rich>=13.0.0
```

### 2. Import in Scanners
```python
from scripts.progress_tracker import ProgressTracker
```

### 3. Pass Tracker to Components
```python
# In orchestrator
self.tracker = ProgressTracker()

# Pass to scanners
scanner = SemgrepScanner(config, tracker=self.tracker)
```

### 4. Add Tracking Calls
```python
# Start scan
scan_id = self.tracker.start_scan("Semgrep", total_files=len(files))

# Update progress in loop
for i, file in enumerate(files):
    # ... scan logic ...
    self.tracker.update_progress(scan_id, completed=i+1)

# Complete
self.tracker.complete_scan(scan_id)
```

### 5. Test in Both Environments
```bash
# Local (with rich UI)
python3 scripts/run_ai_audit.py

# CI simulation (plain logging)
GITHUB_ACTIONS=true python3 scripts/run_ai_audit.py
```

## Best Practices

1. **Always use start/stop**: Ensure proper initialization and cleanup
2. **Use context managers**: Prefer `with tracker.operation()` for automatic cleanup
3. **Handle errors**: Always call `complete_scan()` even on errors
4. **Pass tracker instance**: Share one tracker across all modules
5. **Check stats**: Retrieve statistics for reporting
6. **Test in CI**: Verify output in both TTY and CI environments

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
The tracker should auto-detect and use simple logging. If not:
```python
tracker = ProgressTracker(enable_rich=False)
```

## Architecture

```
ProgressTracker
├── TTY Detection
│   ├── Check sys.stdout.isatty()
│   └── Check CI environment variables
├── Rich UI (when TTY)
│   ├── Live display
│   ├── Progress bars
│   ├── Spinners
│   └── Colored output
└── Simple Logging (when CI)
    ├── Standard logging
    └── Plain text output
```

## File Structure

```
scripts/
├── progress_tracker.py                        # Main implementation
├── PROGRESS_TRACKER_README.md                 # This file
├── PROGRESS_TRACKER_USAGE.md                  # Detailed usage guide
└── PROGRESS_TRACKER_INTEGRATION_EXAMPLE.py    # Integration examples
```

## Code Quality

- **Type hints**: All methods have complete type annotations
- **Docstrings**: Comprehensive documentation for all public methods
- **Error handling**: Graceful degradation and error reporting
- **Logging**: Structured logging at appropriate levels
- **Testing**: Built-in examples and test cases
- **Compatibility**: Works in TTY and CI environments

## Performance

- **Minimal overhead**: Progress updates are lightweight
- **Optimized refresh**: Updates 4 times per second (configurable)
- **Lazy initialization**: Rich components loaded only when needed
- **Clean shutdown**: Proper cleanup of display resources

## License

Part of Argus - see repository license.

## Support

For issues or questions:
1. Check PROGRESS_TRACKER_USAGE.md for detailed documentation
2. Review PROGRESS_TRACKER_INTEGRATION_EXAMPLE.py for examples
3. Run built-in tests: `python3 scripts/progress_tracker.py`

---

**Happy tracking!** 🚀
