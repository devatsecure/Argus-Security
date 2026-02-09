---
name: gen-test
description: Generate tests for an Argus module following project conventions. Use when the user wants to add tests for a module.
---

Generate tests for: $ARGUMENTS

## Pre-Flight Checks (Do These First)

1. **Search for existing tests** — run `grep -rl "<module_name>" tests/` to find any existing coverage. Don't duplicate.
2. **Check existing error handling tests** — `tests/unit/test_error_handling.py` already covers malformed data, rate limiting, circuit breakers, retry exhaustion. Read it before writing similar tests.
3. **Check existing fixtures** — `tests/integration/conftest.py` (972 lines) has comprehensive fixtures. `tests/utils/assertions.py` has domain-specific assertions. `tests/utils/fixtures.py` has `FixtureManager` and `ScannerOutputParser`. Reuse these.

## Project Test Conventions

- **Framework**: pytest with pytest-mock, pytest-asyncio, pytest-cov, pytest-timeout, pytest-xdist
- **Markers**: `@pytest.mark.unit`, `@pytest.mark.integration`, `@pytest.mark.slow`
- **Directory structure**:
  - Unit tests: `tests/unit/test_<module>.py`
  - Integration tests: `tests/integration/test_<workflow>.py`
  - Security regression: `tests/security_regression/`

## Steps

1. Read the source module specified in arguments
2. Search `tests/` for any existing tests covering this module — catalog what's already tested
3. Read 1-2 existing test files for the same or similar module to match patterns
4. Identify gaps: what functions/paths have no test coverage?
5. Generate tests following these rules:
   - Mock external services: `anthropic.Anthropic`, `openai.OpenAI`, `docker.from_env()`
   - Use `pytest.fixture` for shared setup
   - Use `mocker` from pytest-mock for patching
   - Test success paths, error paths, AND edge cases
   - Include security boundary tests (shell injection, path traversal, secret leakage)
   - Use `@pytest.mark.parametrize` for multiple inputs
   - Never use `time.sleep()` — mock time instead
   - Include docstrings describing what each test validates
6. Place unit tests in `tests/unit/test_<module>.py`
7. Run the new tests to verify they pass:
   ```
   pytest tests/unit/test_<module>.py -v --tb=short
   ```
8. Report: coverage percentage, number of new tests, what gaps remain

## Priority Test Targets

These modules have known gaps:
- `scripts/preflight_checker.py` — needs test for shell=True command injection at line 236
- `scripts/gate.py` — needs tests for OPA policy bypass via manipulated auto_fixable and noise_score
- `scripts/docker_manager.py` — needs container escape negative tests
- Any module in `scripts/` not covered in `tests/unit/`
