# Fuzzing Engine Examples

## Overview

The Argus Fuzzing Engine provides AI-guided fuzzing for APIs, functions, and file parsers. It integrates with the existing security scanning pipeline to find runtime crashes and vulnerabilities.

## Features

- **AI-Guided Test Generation**: Uses LLMManager to create intelligent test cases
- **Multi-Target Support**: APIs, functions, file parsers
- **High Performance**: 70,000+ executions/second
- **Crash Deduplication**: Groups similar crashes to reduce noise
- **CWE Mapping**: Automatically maps crashes to CWE IDs
- **SARIF Export**: GitHub-compatible security reports

## Quick Start

### 1. Function Fuzzing

Test a Python function for crashes:

```bash
python scripts/fuzzing_engine.py function \
  --target src/parser.py:parse_xml \
  --duration 30 \
  --output fuzz_results.json
```

### 2. API Fuzzing

Fuzz REST API endpoints from OpenAPI spec:

```bash
python scripts/fuzzing_engine.py api \
  --spec openapi.yaml \
  --base-url https://api.example.com \
  --duration 60 \
  --output api_fuzz.json
```

### 3. File Parser Fuzzing

Test file parsers with malformed inputs:

```bash
python scripts/fuzzing_engine.py parser \
  --target src/parsers.py:parse_json \
  --file-type json \
  --duration 15 \
  --output parser_fuzz.json
```

### 4. CI/CD Integration

Quick fuzzing for continuous integration:

```bash
# Runs for 5 minutes by default
python scripts/fuzzing_engine.py ci --budget 5min
```

## Integration with SAST

Use SAST findings to guide fuzzing:

```bash
# Run Semgrep first
semgrep --config auto --json > sast_findings.json

# Use findings to guide fuzzing
python scripts/fuzzing_engine.py function \
  --target src/auth.py:validate_token \
  --sast-findings sast_findings.json \
  --duration 30
```

## Output Format

### JSON Results

```json
{
  "target": "src/parser.py::parse_xml",
  "duration_seconds": 60,
  "total_iterations": 4709345,
  "unique_crashes": 2,
  "coverage": 0.0,
  "executions_per_second": 77854.0,
  "crashes": [
    {
      "crash_id": "033fb6cb59e6",
      "input_data": "AAAA...",
      "stack_trace": "BufferError: Input too large",
      "crash_type": "exception",
      "severity": "high",
      "cwe": "CWE-703",
      "reproducible": true
    }
  ]
}
```

### SARIF Output

Results are also exported to SARIF for GitHub Security tab integration:

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "Argus Fuzzing Engine",
        "version": "1.0.0"
      }
    },
    "results": [...]
  }]
}
```

## AI-Guided Test Generation

When LLMManager is available, the fuzzing engine uses AI to generate targeted test cases:

```python
from fuzzing_engine import FuzzingEngine
from orchestrator.llm_manager import LLMManager

# Initialize with AI
llm = LLMManager()
engine = FuzzingEngine(llm_manager=llm)

# Generate intelligent test cases
signature = "def authenticate(username: str, password: str) -> bool"
sast_findings = [{"type": "sql_injection", "line": 42}]

test_cases = engine.generate_test_cases(signature, sast_findings)
# Returns: 50+ AI-generated edge cases targeting SQL injection
```

## Crash Detection

The engine detects various crash types:

- **Buffer Overflow**: Large inputs causing memory errors
- **Integer Overflow**: Boundary value violations
- **Null Pointer**: NoneType errors
- **Timeout**: Hanging operations
- **Assertion Failures**: Failed assertions
- **Exceptions**: Unhandled exceptions

## Performance

Typical performance metrics:

- **Function Fuzzing**: 60,000-80,000 exec/s
- **API Fuzzing**: 100-500 req/s (network dependent)
- **Parser Fuzzing**: 10,000-20,000 exec/s

## GitHub Actions Integration

Add to your workflow:

```yaml
- name: Fuzz Critical Functions
  run: |
    python scripts/fuzzing_engine.py function \
      --target src/auth.py:validate_token \
      --duration 10 \
      --output fuzz_results.json

    # Upload results
    gh api repos/${{ github.repository }}/code-scanning/sarifs \
      --input fuzz_results.sarif
```

## Best Practices

1. **Start Small**: Begin with 5-10 minute fuzzing runs
2. **Target Critical Code**: Focus on authentication, parsers, input validation
3. **Use SAST Context**: Provide SAST findings to guide test generation
4. **Review Crashes**: Not all crashes are exploitable - triage carefully
5. **Continuous Fuzzing**: Run regularly in CI/CD

## Example: Real-World Usage

```bash
# Complete fuzzing workflow
set -e

# 1. Run SAST to find potential issues
semgrep --config auto --json > sast.json

# 2. Fuzz authentication functions (high priority)
python scripts/fuzzing_engine.py function \
  --target src/auth.py:validate_password \
  --sast-findings sast.json \
  --duration 30 \
  --output auth_fuzz.json

# 3. Fuzz API endpoints
python scripts/fuzzing_engine.py api \
  --spec openapi.yaml \
  --duration 20 \
  --output api_fuzz.json

# 4. Fuzz file parsers
python scripts/fuzzing_engine.py parser \
  --target src/upload.py:parse_document \
  --file-type pdf \
  --duration 15 \
  --output parser_fuzz.json

# 5. Check for critical crashes
critical_crashes=$(jq '[.crashes[] | select(.severity=="critical")] | length' auth_fuzz.json)

if [ "$critical_crashes" -gt 0 ]; then
  echo "❌ Found $critical_crashes critical crashes!"
  exit 1
fi

echo "✅ Fuzzing complete - no critical issues"
```

## Troubleshooting

### LLMManager Not Available

If you see "LLMManager not available", the engine falls back to template-based generation:

```bash
# Still works without AI, uses predefined payloads
python scripts/fuzzing_engine.py function \
  --target src/parser.py:parse \
  --duration 10
```

### Low Execution Rate

If fuzzing is slow:

1. Reduce test case count
2. Optimize target function
3. Increase timeout: `--timeout 1`

### Too Many Crashes

If you get thousands of duplicate crashes:

- Deduplication is automatic
- Review unique crashes only
- Fix root causes, re-run fuzzing

## Next Steps

- See `scripts/fuzzing_engine.py` for full implementation
- Check `docs/architecture/fuzzing.md` for design details
- Run `python scripts/fuzzing_engine.py --help` for all options
