# Next Fixes Design

**Goal:** Fix remaining bugs, clean up all ruff errors, resolve infrastructure gaps, and add test coverage for untested modules.

**Context:** Follows the 3-wave audit implementation (commits e2e8085 through bce53ab) which addressed 10 of 12 original audit items.

## Wave 1: Bug Fix

**CheckovScanResult not iterable** — `pipeline/stages.py:131` calls `scanner.scan()` which returns a `CheckovScanResult` dataclass, but line 100 tries `ctx.findings.extend(result)` treating it as a list. The `hybrid_analyzer` path handles this correctly via `scanner_runners.py:163` by accessing `.findings`. Fix: extract `.findings` from the result, convert `CheckovFinding` objects to dicts.

## Wave 2: Ruff Cleanup + Config Fix

- **run_ai_audit.py** (28 errors): 18 unused imports (F401), 4 import-not-at-top (E402), 2 unsorted imports (I001), 2 f-strings without placeholders (F541), 1 unused variable (F841), 1 simplifiable conditional (SIM108). Target: 0 errors.
- **hybrid_analyzer.py** (8 errors): Unused imports, import ordering. Target: 0 errors.
- **max_files default mismatch**: `config_loader.py:95` defaults to `50`, `orchestrator/config.py:46` defaults to `"100"`. Align to `50` (config_loader is the canonical source).

## Wave 3: Infrastructure

- **Falco in Dockerfile.complete**: Add Falco installation OR add clear skip/warning message in `runtime_security_monitor.py` when Falco is not found.
- **ZAP is active** (corrected): ZAP IS wired in `phase1_scanning.py:305-331` via `scan_source()` and defaults enabled (`enable_zap_baseline=True`). Keep ZAP in Dockerfile.complete. No action needed.

## Wave 4: Test Coverage

Write tests for the 5-6 highest-impact untested modules. Candidates: `enrichment_pipeline.py` integration tests, `pipeline/stages.py`, `scanner_runners.py`, `config_loader.py`, `threat_model_generator.py`.

## Approach

Sequential waves, parallel agents within each wave. Each wave verified before proceeding to next.
