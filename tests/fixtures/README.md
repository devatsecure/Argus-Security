# Test Fixtures

Fixtures used by unit, integration, and security-regression tests.

| Fixture | Purpose |
|---------|---------|
| **vulnerable_app/** | Intentionally vulnerable code (e.g. SQL concatenation, `shell=True`) for scanner and remediation tests. **Do not use with untrusted input** — for test runs only. |
| **scanner_outputs/** | Sample Semgrep, Trivy, Checkov, Nuclei, TruffleHog JSON outputs for normalizers and pipeline tests. |
| **python_cli/** | Minimal Python CLI app for CLI and execution tests. |
| **web_app/** | Web app fixtures where used. |

Security regression tests under `tests/security_regression/` reference fixtures to assert that Argus detects or fixes specific vulnerability patterns.
