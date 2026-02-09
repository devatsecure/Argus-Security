---
name: run-audit
description: Run the Argus 6-phase security audit pipeline. Use when the user wants to run a security scan or audit.
---

Run the Argus security audit for: $ARGUMENTS

## Current State
- Branch: !`git branch --show-current`
- Uncommitted changes: !`git status --short | head -10`

## Known Vulnerabilities to Flag

These are confirmed issues in Argus itself — always flag them in audit output:
- `scripts/preflight_checker.py:236`: `shell=True` with user-controlled command — command injection
- `policy/rego/pr.rego:239-256`: `auto_fixable=true` bypasses gate
- `policy/rego/pr.rego`: `noise_score` is unsigned, can be set to 1.0 to suppress findings
- `scripts/docker_manager.py:197`: `read_only=False` on sandbox containers
- `scripts/docker_manager.py`: No Seccomp/AppArmor profiles

## Steps

1. Parse arguments to determine project type (default: `backend-api`). Valid types: `backend-api`, `frontend-app`, `library`, `infrastructure`, `full-stack`.
2. Run the 6-phase audit:
   ```
   python scripts/run_ai_audit.py --project-type <type>
   ```
3. Summarize findings by phase:
   - **Phase 1** (Scanners): Total findings from Semgrep, Trivy, Checkov, TruffleHog, Gitleaks
   - **Phase 2** (AI Triage): Noise-filtered count, false positive predictions
   - **Phase 3** (Multi-Agent): Consensus findings, agent agreement levels
   - **Phase 4** (Sandbox): Exploitable vs not-exploitable counts
   - **Phase 5** (Policy Gates): Pass/fail status per gate
   - **Phase 6** (Reports): Output file locations
4. Highlight any BLOCKER-level findings that would fail a PR gate
5. Cross-reference findings against the Known Vulnerabilities list above — if any known issue is NOT flagged by the scanners, report that as a scanner gap
6. If `--fix` is in arguments, also run `python scripts/remediation_engine.py` on critical findings
