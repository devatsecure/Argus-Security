# Security Test Generator

The Security Test Generator is an AI-powered tool that automatically generates security regression tests from discovered vulnerabilities. It supports both Python (pytest) and JavaScript (Jest) test frameworks.

## Overview

This tool takes vulnerability findings from security scanners (TruffleHog, Gitleaks, Semgrep, Trivy, etc.) and generates comprehensive test suites that include:

- **Exploit tests**: Verify that vulnerabilities are exploitable (positive test cases)
- **Fix verification tests**: Ensure that proper input validation prevents exploitation (negative test cases)
- **Regression tests**: Guard against reintroduction of fixed vulnerabilities

## Features

### AI-Powered Generation
- Uses Claude/OpenAI/Ollama to generate context-aware security tests
- Analyzes vulnerability details and code snippets to create realistic tests
- Generates appropriate test payloads for different vulnerability types

### Template Fallback
- When AI is unavailable, uses high-quality templates for common vulnerability types
- Supports SQL injection, XSS, command injection, path traversal, XXE, and more
- Templates include TODO markers for easy customization

### Multi-Language Support
- **Python**: Generates pytest tests with fixtures and proper assertions
- **JavaScript**: Generates Jest tests with async/await and supertest integration
- Automatically detects language from file extensions and code content

### Vulnerability Coverage
- SQL injection
- Cross-site scripting (XSS)
- Command injection
- Path traversal / Directory traversal
- XML external entity (XXE) attacks
- And more...

## Usage

### Command Line Interface

```bash
# Basic usage
python scripts/security_test_generator.py \
  --input findings.json \
  --output-dir tests/security/

# With custom filename
python scripts/security_test_generator.py \
  --input findings.json \
  --output-dir tests/security/ \
  --filename test_custom_security.py

# Debug mode
python scripts/security_test_generator.py \
  --input findings.json \
  --debug
```

### Input Format

The tool accepts UnifiedFinding format (JSON):

```json
{
  "findings": [
    {
      "id": "sql-injection-001",
      "type": "sql-injection",
      "severity": "high",
      "path": "app/users/views.py",
      "description": "SQL injection vulnerability in user search endpoint",
      "code_snippet": "query = f\"SELECT * FROM users WHERE name = '{user_input}'\"\ncursor.execute(query)"
    }
  ]
}
```

Or as a direct array:

```json
[
  {
    "id": "xss-002",
    "type": "xss",
    "severity": "medium",
    "path": "frontend/src/components/UserProfile.jsx",
    "description": "XSS vulnerability",
    "code_snippet": "return <div dangerouslySetInnerHTML={{ __html: name }} />;"
  }
]
```

### Python API

```python
from scripts.security_test_generator import SecurityTestGenerator

# Initialize generator
generator = SecurityTestGenerator(debug=True)

# Generate test suite
findings = [
    {
        "id": "sql-injection-001",
        "type": "sql-injection",
        "path": "app/views.py",
        "description": "SQL injection vulnerability",
        "code_snippet": "query = f'SELECT * FROM users WHERE id={user_id}'"
    }
]

suite = generator.generate_test_suite(
    findings=findings,
    output_path="tests/security/",
    filename="test_sql_injection.py"
)

# Print statistics
generator.print_stats()

# Generate regression test for fixed vulnerability
fixed_finding = {
    "id": "xss-fixed-123",
    "type": "xss",
    "description": "Previously exploitable XSS"
}

regression_test = generator.generate_regression_test(
    fixed_finding,
    language="python"
)
print(regression_test)
```

## Output Examples

### Python (pytest) Output

```python
import pytest
import requests
import json
from typing import Optional, Any
from pathlib import Path


@pytest.fixture
def api_client():
    """Fixture for API testing"""
    session = requests.Session()
    session.headers.update({"User-Agent": "SecurityTest/1.0"})
    yield session
    session.close()


def test_sql_injection_001_exploit():
    """
    Test exploitation of sql-injection vulnerability

    Finding: sql_injection_001
    File: views.py
    Description: SQL injection vulnerability in user search endpoint
    """
    # Test with malicious payloads
    test_payloads = ["' OR '1'='1", '1; DROP TABLE users--', "' UNION SELECT NULL--"]

    for payload in test_payloads:
        response = requests.get(
            "http://localhost:8000/vulnerable-endpoint",
            params={"input": payload}
        )

        # Verify vulnerability is exploitable
        assert response.status_code in [200, 400, 500]


def test_sql_injection_001_fix_verification():
    """
    Verify that sql-injection vulnerability is properly fixed

    This test should PASS after the vulnerability is fixed.
    """
    # Test with safe inputs
    safe_inputs = ["normal_input", "test123", "valid-data"]

    for safe_input in safe_inputs:
        response = requests.get(
            "http://localhost:8000/vulnerable-endpoint",
            params={"input": safe_input}
        )

        # Verify safe inputs are handled correctly
        assert response.status_code == 200
```

### JavaScript (Jest) Output

```javascript
const request = require('supertest');
const app = require('../app');


describe('Security Tests - Generated', () => {
    beforeAll(() => {
        // Initialize test environment
    });

    afterAll(() => {
        // Cleanup
    });

    describe('xss_002 - xss', () => {
        test('should be exploitable with malicious payloads', async () => {
            const testPayloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"];

            for (const payload of testPayloads) {
                const response = await request(app)
                    .get('/vulnerable-endpoint')
                    .query({ input: payload });

                expect([200, 400, 500]).toContain(response.status);
            }
        });

        test('should properly validate safe inputs', async () => {
            const safeInputs = ['normal_input', 'test123', 'valid-data'];

            for (const safeInput of safeInputs) {
                const response = await request(app)
                    .get('/vulnerable-endpoint')
                    .query({ input: safeInput });

                expect(response.status).toBe(200);
            }
        });
    });
});
```

## Integration with Argus Workflow

### 1. Scan for Vulnerabilities

```bash
python scripts/run_ai_audit.py \
  --project-type backend-api \
  --ai-provider anthropic \
  --output-file findings.json
```

### 2. Generate Security Tests

```bash
python scripts/security_test_generator.py \
  --input findings.json \
  --output-dir tests/security/
```

### 3. Run Tests

```bash
# Python
pytest tests/security/test_security_generated.py -v

# JavaScript
npm test tests/security/security.test.js
```

### 4. Fix Vulnerabilities and Verify

After fixing vulnerabilities, the "fix verification" tests should pass:

```bash
pytest tests/security/ -k "fix_verification" -v
```

### 5. Create Regression Tests

For confirmed fixes, generate regression tests:

```python
from scripts.security_test_generator import SecurityTestGenerator

generator = SecurityTestGenerator()

# Load fixed findings
with open('fixed_vulnerabilities.json') as f:
    fixed_findings = json.load(f)

# Generate regression tests
for finding in fixed_findings:
    test_code = generator.generate_regression_test(finding)
    # Add to regression test suite
```

## Configuration

### Environment Variables

- `ANTHROPIC_API_KEY`: Claude API key for AI-powered test generation
- `OPENAI_API_KEY`: OpenAI API key (alternative to Claude)
- `OLLAMA_HOST`: Ollama host for local LLM (default: http://localhost:11434)

### Customization

The generator includes configurable payload patterns in `VULN_PATTERNS`:

```python
VULN_PATTERNS = {
    "sql-injection": {
        "test_type": "injection",
        "payloads": ["' OR '1'='1", "1; DROP TABLE users--", "' UNION SELECT NULL--"],
    },
    "xss": {
        "test_type": "injection",
        "payloads": ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"],
    },
    # Add custom patterns here...
}
```

## Best Practices

### 1. Review Generated Tests
Always review and customize generated tests before running them. Templates include `TODO` markers indicating sections that need customization.

### 2. Update Endpoints and Functions
Replace placeholder URLs and function names with actual application code:

```python
# Before (template)
response = requests.get("http://localhost:8000/vulnerable-endpoint")

# After (customized)
response = requests.get("http://localhost:8000/api/users/search")
```

### 3. Use Fixtures for Setup
Leverage pytest fixtures for common setup tasks:

```python
@pytest.fixture
def authenticated_client():
    client = requests.Session()
    client.headers['Authorization'] = 'Bearer test-token'
    return client

def test_with_auth(authenticated_client):
    response = authenticated_client.get('/protected-endpoint')
    assert response.status_code == 200
```

### 4. Separate Exploit and Regression Tests
Keep exploit tests (for validating fixes) separate from regression tests (for CI/CD):

```
tests/security/
├── exploits/           # Tests to verify vulnerabilities (run manually)
│   └── test_sql_injection_exploits.py
└── regression/         # Tests to prevent regressions (run in CI)
    └── test_security_regression.py
```

### 5. Integrate with CI/CD
Run regression tests in CI to catch reintroduced vulnerabilities:

```yaml
# .github/workflows/security-tests.yml
- name: Run Security Regression Tests
  run: pytest tests/security/regression/ -v --tb=short
```

## Troubleshooting

### LLM Not Available
If you see "LLM manager not available", the tool will use template-based generation:

```
WARNING:__main__:LLM manager not available, using fallback templates
```

This is expected and the templates still provide high-quality tests.

### Invalid Input Format
Ensure your findings JSON matches the expected format:

```
❌ Error: Invalid input format. Expected list or dict with 'findings' key
```

Check that your JSON is either:
- A direct array: `[{...}, {...}]`
- Or wrapped: `{"findings": [{...}, {...}]}`

### Language Detection Issues
If the wrong language is detected, explicitly set it in code:

```python
generator = SecurityTestGenerator()
suite = generator.generate_test_suite(findings)
suite.language = "javascript"  # Force JavaScript
```

Or filter findings by language before generation.

## Statistics and Reporting

The generator tracks and reports statistics:

```
==================================================
Security Test Generation Statistics
==================================================
Total findings processed: 15
Tests successfully generated: 14
Tests failed to generate: 1

Languages detected:
  - python: 10 findings
  - javascript: 5 findings
==================================================
```

## Advanced Usage

### Batch Processing

```bash
# Generate tests for all findings in a directory
for file in findings/*.json; do
    python scripts/security_test_generator.py \
        --input "$file" \
        --output-dir "tests/security/$(basename $file .json)/"
done
```

### Custom LLM Integration

```python
from scripts.security_test_generator import SecurityTestGenerator
from orchestrator.llm_manager import LLMManager

# Use custom LLM configuration
llm = LLMManager(provider="anthropic", model="claude-opus-4")
generator = SecurityTestGenerator(llm_manager=llm)

suite = generator.generate_test_suite(findings)
```

### Programmatic Filtering

```python
# Generate tests only for high severity findings
high_severity = [f for f in findings if f.get("severity") == "high"]
suite = generator.generate_test_suite(high_severity)

# Generate tests for specific vulnerability types
sql_findings = [f for f in findings if "sql" in f.get("type", "").lower()]
suite = generator.generate_test_suite(sql_findings)
```

## Related Documentation

- [Scanner Reference](references/scanner-reference.md) - Details on security scanners
- [AI Triage Strategy](adrs/0003-ai-triage-strategy.md) - AI-powered analysis approach
- [Best Practices](best-practices.md) - Security testing best practices
- [Testing Guide](../tests/README.md) - General testing documentation

## Contributing

To add support for new vulnerability types:

1. Add payload patterns to `VULN_PATTERNS` dict
2. Create template methods for Python/JavaScript
3. Update vulnerability type normalization in `_normalize_vuln_type()`
4. Add test cases to verify generation

Example:

```python
# Add to VULN_PATTERNS
"ssrf": {
    "test_type": "injection",
    "payloads": ["http://169.254.169.254/latest/meta-data/", "http://localhost:8080/admin"],
}

# Add to normalization
mappings = {
    # existing mappings...
    "server-side-request-forgery": "ssrf",
}
```
