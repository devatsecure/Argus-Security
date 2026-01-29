# Context-Aware HeuristicScanner - Quick Reference

## What It Does

The enhanced `HeuristicScanner` automatically detects whether code is from:
- **Test files** (skipped to avoid false positives from test fixtures)
- **Documentation** (skipped to avoid false positives from examples)
- **Production code** (fully scanned for security issues)

## Usage

```python
from scripts.run_ai_audit import HeuristicScanner

scanner = HeuristicScanner()

# Scan a file
flags = scanner.scan_file(file_path, content)

# flags will be:
# - Empty list [] for test files and documentation
# - List of issue flags for production code with problems
```

## File Type Detection

### Automatically Detected as Test Files
- `test_*.py`, `*_test.py`
- `*.test.js`, `*.spec.ts`
- Files in `tests/`, `test/`, `__tests__/` directories
- Files with test framework imports (pytest, jest, mocha)
- Files with test patterns (`def test_*`, `it()`, `describe()`)

### Automatically Detected as Documentation
- `*.md` files
- Files in `docs/`, `examples/`, `samples/`, `demo/` directories
- Files with markdown headers and code blocks
- README files

### Treated as Production Code
- Everything else that doesn't match test/doc patterns

## Secret Detection Intelligence

### Test Secrets (Ignored)
```python
password = "TEST_PASSWORD_123"           # ✓ Recognized as test data
api_key = "EXAMPLE_API_KEY_12345678"     # ✓ Recognized as test data
token = "test_token_value"               # ✓ Recognized as test data
secret = "dummy_secret_12345678"         # ✓ Recognized as test data
api_key = "123456789012"                 # ✓ Simple numeric pattern
```

### Real Secrets (Flagged)
```python
password = "kJ8#mQ9$pL2@nB5!"            # ✗ Complex, real-looking secret
api_key = "sk-proj-abc123xyz789"         # ✗ Real API key format
token = "ghp_1234567890abcdef"           # ✗ GitHub token format
```

## Security Patterns (Always Checked in Production Code)

### Dangerous Code Execution
```python
eval(user_input)        # Flagged: dangerous-exec
exec(code)              # Flagged: dangerous-exec
__import__(module)      # Flagged: dangerous-exec
```

### SQL Injection
```python
query = "SELECT * FROM users WHERE id=" + user_id  # Flagged: sql-concatenation
```

### XSS Risk
```javascript
element.innerHTML = userInput;                      // Flagged: xss-risk
<div dangerouslySetInnerHTML={{__html: html}} />   // Flagged: xss-risk
```

### Performance Issues (Only in Production)
```python
for i in items:
    for j in items:       # Flagged: nested-loops (NOT flagged in tests)
        process(i, j)
```

## Confidence Levels

### High Confidence (>0.5)
- File is skipped entirely
- Example: `tests/test_auth.py` with pytest import

### Medium Confidence (0.3-0.5)
- File is scanned but flagged with uncertainty
- Example: File with assertions but no test framework

### Low Confidence (<0.3)
- Treated as production code
- Fully scanned for all patterns

## Examples

### ✓ Test File - No False Positives
```python
# tests/test_api.py
import pytest

def test_authentication():
    """Test API authentication with dummy credentials"""
    api_key = "sk-1234567890abcdef"  # This won't be flagged!
    response = client.authenticate(api_key)
    assert response.status_code == 200
```
**Result**: File skipped, no flags

### ✓ Documentation - No False Positives
```markdown
# README.md

## Quick Start

```python
password = "your_password_here"
api_key = "your_api_key_1234567890"
```
```
**Result**: File skipped, no flags

### ✗ Production Code - Correctly Flagged
```python
# src/api/client.py
def connect_to_api():
    api_key = "sk-proj-real-key-abc123"  # This WILL be flagged!
    return client.connect(api_key)
```
**Result**: `['hardcoded-secrets']`

### ✓ Production Code with Test Data - Smart Detection
```python
# src/models/user.py
def create_test_user():
    """Create a test user with dummy credentials"""
    password = "TEST_PASSWORD_123"  # Recognized as test data
    return User.create(username="test_user", password=password)
```
**Result**: No flag (TEST_PASSWORD pattern detected)

## Testing

### Run All Tests
```bash
pytest tests/test_heuristic_scanner_context.py -v
# Expected: 27 passed
```

### Run Specific Test Categories
```bash
# File type detection
pytest tests/test_heuristic_scanner_context.py::TestFileTypeDetection -v

# Secret detection
pytest tests/test_heuristic_scanner_context.py::TestTestSecretDetection -v

# Edge cases
pytest tests/test_heuristic_scanner_context.py::TestEdgeCases -v
```

## Customization

### Add Custom Test Patterns
```python
scanner = HeuristicScanner()
scanner.test_patterns.append(r'spec/.*\.rb$')  # Ruby spec files
scanner.test_patterns.append(r'.*\.unit\.ts$')  # TypeScript unit tests
```

### Add Custom Test Data Patterns
```python
scanner.test_data_patterns.append(r'STAGING_\w+')    # Staging credentials
scanner.test_data_patterns.append(r'LOCAL_DEV_\w+')  # Local dev credentials
```

### Adjust Confidence Threshold
Modify `_detect_context` method:
```python
# In scripts/run_ai_audit.py, line ~158-165
test_content_indicators = [
    (r'import\s+(unittest|pytest)', 0.6, "Test framework import"),  # Increased from 0.4
    # ... other patterns
]
```

## Troubleshooting

### Issue: Test file is being scanned
**Solution**: Check if file matches test patterns
```python
scanner._detect_context("path/to/file.py", content)
# Should return test_confidence > 0.5
```

### Issue: Production secret not flagged
**Solution**: Verify secret doesn't match test patterns
```python
scanner._is_test_secret('api_key = "your_secret"')
# Should return False for real secrets
```

### Issue: Too many false positives
**Solution**: Increase confidence thresholds or add patterns
```python
# In scan_file method, line ~238-244
if context['test_confidence'] > 0.4:  # Lower from 0.5 for more aggressive skipping
    return []
```

## Integration with Argus Pipeline

```
Phase 1: Scanner Orchestration
  └─> HeuristicScanner filters files
      ├─> Skip: tests/test_*.py (test files)
      ├─> Skip: docs/*.md (documentation)
      └─> Scan: src/*.py (production code)

Phase 2: AI Enrichment
  └─> Processes only relevant findings

Phase 3: Multi-Agent Review
  └─> Reviews context-filtered results

... (Phases 4-6)
```

## Performance

- **Overhead**: ~2-5ms per file for context detection
- **Memory**: Negligible (patterns compiled once)
- **Scaling**: Linear with number of files
- **Cache**: Context detection can be cached per file

## Support

For issues or enhancements:
1. Check test coverage: `pytest tests/test_heuristic_scanner_context.py -v`
2. Review implementation: `scripts/run_ai_audit.py` lines 71-320
3. See full documentation: `CONTEXT_AWARE_HEURISTIC_SCANNER_SUMMARY.md`
