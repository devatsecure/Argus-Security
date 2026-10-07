# Project Maturity Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans to implement this plan task-by-task. Track verification below.

**Goal:** Make scan outcomes trustworthy and the published Python package usable.

**Architecture:** Preserve the phase pipeline; carry scanner execution and policy
state in typed result fields. Add a packaging compatibility entry point and bundle
existing resources without duplicating source assets.

**Tech Stack:** Python, dataclasses, pytest, setuptools, OPA/Rego, GitHub Actions.

**Spec:** [Design](../specs/2026-10-07-project-maturity-design.md)

## Global Constraints

- Python >=3.10; no paid LLM calls or live-target scanning needed for validation.
- No force push, rule changes, release publication, or unrelated repository edits.
- Existing source-checkout commands remain supported.

## Review Focus

- Requested scanners whose constructors disable themselves must remain failures.
- Scanner error dictionaries and malformed output must not become clean scans.
- No findings must still enforce release metadata requirements.
- Report filtering must not permit policy/high-severity failures to exit zero.
- An installed wheel must work without importing files from the source checkout.

## Task 1: Scanner execution and report contracts

**Files:** `scripts/hybrid/{models,scanner_runners,report}.py`,
`scripts/hybrid/phases/{phase1_scanning,phase6_reporting}.py`,
`scripts/hybrid_analyzer.py`, `tests/test_scan_outcomes.py`.

**Interfaces:** `HybridScanResult.scanner_health`, `scan_status`,
`policy_gate_result`, `vulnerability_chains`; runner errors reach Phase 1.

- [x] Write tests for exceptions, error dictionaries, failed initialization,
  empty successful scans, and persisted JSON/SARIF/Markdown health.
- [x] Run the tests and confirm contract failures.
- [x] Preserve requested flags; propagate scanner errors; serialize outcome fields
  before saving. Preserve verified-secret evidence.
- [x] Run outcome tests and existing scanner/phase/report tests.

## Task 2: Enforce policy and CLI outcomes

**Files:** `scripts/gate.py`, `scripts/hybrid/phases/phase5_policy.py`,
`scripts/hybrid/cli.py`, `tests/test_scan_outcomes.py`.

**Interfaces:** policy `decision` is `pass`, `fail`, or `error`; CLI exit codes
0/1/2 distinguish pass, finding/policy rejection, and incomplete execution.

- [x] Add failing tests for empty release scans, normalized policy evidence,
  invalid decisions, missing OPA, and CLI precedence including report filters.
- [x] Evaluate every scan; make library failures exceptions; convert failures to
  reportable error decisions. Use actual policy state in the CLI.
- [x] Run regression tests, real OPA fixtures if available, and existing policy tests.

## Task 3: Installable package and regression CI

**Files:** `setup.py`, `pyproject.toml`, `MANIFEST.in`, `scripts/cli.py`,
`scripts/resource_paths.py`, resource consumers, packaging tests,
`.github/workflows/maturity-contracts.yml`.

**Interfaces:** installed `argus-scan`, `argus-audit`, `argus-gate`; resource resolver
works in checkout and wheel. Heavy scanner binaries remain separately installed.

- [x] Confirm the baseline wheel is missing code (observed: only five metadata files).
- [x] Add build/install smoke verification from an unrelated working directory.
- [x] Package code and resources; align runtime dependencies and supported Python.
- [x] Add independent CI for boundary regressions and wheel installation.
- [x] Run wheel smoke, changed-file lint, broad tests, and fresh code review.

## Task 4: Review, evidence, and delivery

**Files:** `docs/PROJECT_MATURITY_REVIEW.md`, `README.md`, this plan.

- [x] Publish strengths, gaps, sourced peer comparison, prioritized roadmap, and
  measured validation results. Correct unsupported headline claims.
- [x] Review all changes and fix material review findings.

Delivery procedure: commit the verified changes, push to main without overriding
branch protections, and verify the remote SHA. The delivery message records the
resulting commit and remote verification.

## Execution record

- Baseline: `24b72c7` (fast-forwarded clean checkout to preserve upstream docs).
- Baseline wheel built successfully but contains no application code.
- Baseline Ruff: 802 findings across scripts/tests; not introduced by this work.
- Execution is authorized by the user's request to plan, implement, and push;
  no additional design-approval round is needed.


### Implementation decisions

- Expanded Task 2 through the composite Action: unique report directories,
  scan-only JSON selection, policy-aware exit propagation, and rejection of
  stale reports after a crash. Full mode installs declared Python dependencies
  and runs from the Action source tree so built-in resources remain available.
- Retained source-checkout commands and introduced a compatibility bootstrap for
  installed commands; a repository-wide import migration remains later work.
- Required real OPA instead of silently substituting a weaker test policy.
  Requested missing scanners and missing OPA are now explicit execution errors;
  this intentional behavior change is documented in the README.
- Preserved immutable copies of API-verified secret evidence before AI stages
  and final enrichment. AI suppression or mutation cannot waive that evidence.
- Corrected existing fixture setup and nondeterministic set parametrization
  discovered during broad testing; repaired existing workflow pin/eval failures.
- Milestones 2–4 in the review are follow-up roadmap work. This implementation
  completes Milestone 1, with no comparative detection-accuracy claim.

### Review and regression evidence

A fresh reviewer identified four material gaps in the first implementation:
verified secrets could still be removed by AI, Semgrep raw errors were lost,
a sole unavailable scanner failed before reporting, and the Action could reuse
an old report after a crash. Reproducing tests failed before the repairs and
passed afterward. All four findings are resolved.

- Final focused contract/scanner/phase/CLI/workflow/MCP/temporal run:
  **388 passed, 1 skipped**, Python 3.11.15, pytest 9.1.1, real OPA on PATH.
- Action setup follow-up: **13 passed, 1 skipped**, including execution from a
  different project directory while resolving the Action's built-in policy.
- `opa test policy/rego -v`: **23/23 passed**, OPA 1.21.1. The local binary's
  official SHA-256 was checked before execution. CI pins and checks the Linux
  binary separately.
- Source archive → wheel build passed. The wheel was installed with its declared
  dependencies into a clean virtual environment. `argus-scan --help`,
  `argus-audit --help`, and `argus-gate --help` all passed from `/private/tmp`.
  Distribution tests also exercise bundled policies, custom rules, configuration
  profiles, and agent prompts outside the checkout. The installed policy gate
  also evaluated real OPA policies: an empty PR scan exited 0, and an empty
  release scan without required metadata exited 1.
- Ruff check and format passed for every changed Python file. Repository-wide
  baseline lint debt remains documented rather than suppressed.
- Diff whitespace check preserves the README's existing CRLF convention:
  `git -c core.whitespace=cr-at-eol diff --check`.
- The first full run with a 120-second timeout completed with 4,116 passes,
  110 skips, and two failures: the command suppressed a warning expected by a
  logging test, and an all-scanners-disabled fixture still enabled Gitleaks.
  Both pass with normal warning capture and the corrected fixture. The final
  full-suite rerun is recorded below.


### Final full-suite verification

```sh
PATH=/private/tmp/argus-review-venv/bin:$PATH python -m pytest -q -n 4 \
  -o addopts='' --timeout=120 --show-capture=no --log-level=WARNING
```

**Result: 4,118 passed, 110 skipped, 40 subtests passed, 12 warnings, zero
failures, 260.32 seconds.** No tests were deselected. Skips retain the repository's
optional-runtime requirements. Existing warnings include tests returning values
instead of asserting and a deprecated class-scoped fixture definition; these are
part of the test-quality backlog. This result does not imply that unavailable
external scanner or container integrations were exercised.

Changed Python files also pass Ruff check and format verification (31 files).
The source archive, wheel, CLI smoke checks, and real installed policy checks
pass. No package release was published.
