---
name: fix-scanner
description: Diagnose and fix scanner wiring issues in hybrid_analyzer.py and scanner_runners.py. Use when Docker pipeline runs fail with scanner init or method errors.
user-invocable: false
---

Diagnose and fix scanner wiring issues.

This skill runs automatically when a Docker pipeline scan fails with scanner initialization or method call errors. It systematically verifies that all scanner instantiation and method invocations in the orchestrator match the actual scanner module signatures.

## Step 1: Audit Scanner Initialization in hybrid_analyzer.py

1. Read `scripts/hybrid_analyzer.py` constructor -- find all scanner init blocks (approximately lines 325-450).
2. For EACH scanner init block found:
   - Identify the scanner class being instantiated and the kwargs being passed.
   - Read the actual scanner module's `__init__` method signature (e.g., `scripts/fuzzing_engine.py`, `scripts/runtime_monitor.py`, `scripts/dast_scanner.py`, `scripts/trufflehog_scanner.py`, etc.).
   - Compare the kwargs passed in `hybrid_analyzer.py` against the actual `__init__` parameter names.
   - Flag any mismatch. Common issues:
     - Passing `ai_provider` when the constructor expects `llm_manager`
     - Passing extra kwargs the constructor does not accept
     - Missing required positional arguments

## Step 2: Audit Scanner Method Calls in scanner_runners.py

1. Read `scripts/hybrid/scanner_runners.py` -- find all `run_*` functions.
2. For EACH runner function:
   - Find the method call on the scanner object (e.g., `scanner.scan()`, `monitor.monitor()`, `engine.fuzz()`).
   - Read the actual scanner module and verify that exact method name exists on the class.
   - Flag any mismatch. Common issues:
     - Calling `scan()` when the actual method is `fuzz_function()`
     - Calling `monitor()` when the actual method is `monitor_realtime()`
     - Wrong return type expectations (e.g., expecting a dict when the method returns a list)

## Step 3: Known Correct Patterns (Do NOT Flag These)

These have been verified as correct -- skip them during diagnosis:
- `FuzzingEngine(llm_manager=self.ai_client)` -- correct kwarg name
- `RuntimeSecurityMonitor()` -- no args required, correct
- `TruffleHogScanner()` -- optional config arg, correct
- `DASTScanner(target_url=..., openapi_spec=...)` -- correct kwargs
- `run_fuzzing` calls `scanner.fuzz_function()` -- correct method name
- `run_runtime_security` calls `monitor.monitor_realtime()` -- correct method name

If any of these patterns appear during the audit, confirm they are correct and move on.

## Step 4: Cache and Filesystem Checks

1. Verify cache directories are writable:
   ```
   test -w .argus-cache/ 2>/dev/null && echo "OK" || echo "NOT WRITABLE: .argus-cache/"
   test -w /tmp/argus-cache/ 2>/dev/null && echo "OK" || echo "NOT WRITABLE: /tmp/argus-cache/"
   test -w /var/tmp/ 2>/dev/null && echo "OK" || echo "NOT WRITABLE: /var/tmp/"
   ```
   If any cache directory does not exist, create it. If it exists but is not writable, flag the permission issue.

2. Docker socket check for sandbox validation:
   ```
   ls -la /var/run/docker.sock
   ```
   Verify the socket exists and the current user has read/write access. If not, this will prevent Phase 4 (Sandbox Validation) from working.

## Step 5: Apply Fixes

For each mismatch found in Steps 1-2:
1. Determine the correct fix by reading the target module's actual signature.
2. Edit `scripts/hybrid_analyzer.py` or `scripts/hybrid/scanner_runners.py` to match the actual signatures.
3. After applying fixes, verify the changes are syntactically correct:
   ```
   python -c "import ast; ast.parse(open('scripts/hybrid_analyzer.py').read())"
   python -c "import ast; ast.parse(open('scripts/hybrid/scanner_runners.py').read())"
   ```

## Step 6: Report

Summarize all findings:
- **Mismatches found**: List each init kwarg or method name mismatch with file, line number, expected vs actual.
- **Fixes applied**: List each change made.
- **Cache/filesystem issues**: Any directory or permission problems found.
- **Docker socket status**: Whether sandbox validation will work.
- Recommend re-running the Docker scan to verify fixes.
