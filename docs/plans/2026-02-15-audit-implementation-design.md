# Audit Implementation Design — 2026-02-15

## Context

Code audit identified 12 action items across 3 tiers (Quick Wins, Medium-term, Long-term). Exploration confirmed most findings but corrected test coverage data (112 test files exist, not 34).

## Scope

Implementing 11 of 12 items. Item #10 (DI container) is explicitly out of scope per user decision.

## Approach: Sequential Agent Waves

Three waves, each merged to main before the next starts.

---

## Wave 1 — Quick Wins

**Branch**: `feat/audit-wave1-quickwins`
**Agents**: 4 parallel
**Risk**: Low

### Agent 1: fix-bare-except
- **Files**: `scripts/dashboard/observability_dashboard.py` (lines 286, 311), `scripts/feedback_loop.py`, `scripts/sandbox_integration.py`
- **Change**: Replace bare `except:` with specific exception types (`Exception`, `OSError`, `json.JSONDecodeError`, etc.)
- **Rule**: Read context around each bare except to determine the right exception type

### Agent 2: fix-temp-files
- **Files**: `scripts/gate.py` (~line 131), `scripts/fuzzing_engine.py` (~line 927), `scripts/agents/zap_agent.py` (~line 228), `scripts/agents/nuclei_agent.py` (~line 277)
- **Change**: Add `finally` blocks or `atexit` handlers to clean up `delete=False` temp files
- **Pattern**: Wrap in try/finally or use a cleanup list with atexit.register

### Agent 3: fix-duplicate
- **File**: `scripts/threat_model_generator.py`
- **Change**: Delete the second `_detect_frameworks` method (starts around line 668). Python uses last definition, so the first one (line 186) is already dead code — delete whichever is less complete, keep the better one.

### Agent 4: fix-env-vars
- **File**: `scripts/hybrid/cli.py`
- **Change**: Validate CLI args before writing to `os.environ`. Add type checking, sanitize string values, and add a comment explaining why env vars are used (if downstream modules require it) or refactor to pass via config dict.

### Wave 1 Verification
```bash
ruff check scripts/ && ruff format scripts/
pytest -v --cov=scripts -x
```

---

## Wave 2 — Refactoring

**Branch**: `feat/audit-wave2-refactoring`
**Agents**: 4 (some sequential due to shared file concerns)
**Risk**: Medium

### Agent 5: extract-run-audit
- **File**: `scripts/run_ai_audit.py`
- **Change**: Extract `run_audit()` (989 lines) into phase functions within the same file:
  - `_run_phase1_research(context_tracker)` — file selection, research
  - `_run_phase2_planning(context_tracker)` — focus identification
  - `_run_phase2_deep_analysis(context_tracker)` — AISLE deep analysis
  - `_run_phase3_implementation(context_tracker)` — detailed analysis
  - `run_audit()` becomes a thin orchestrator calling these functions
- **Constraint**: Same file, same class/module. No new imports. Preserve all return values and side effects.

### Agent 6: lazy-load-init
- **File**: `scripts/hybrid_analyzer.py`
- **Change**: Wrap module imports in `__init__` behind config guards:
  ```python
  # Before:
  try:
      from epss_scorer import EPSSScorer
      self.epss_scorer = EPSSScorer()
  except ImportError:
      self.epss_scorer = None

  # After:
  self.epss_scorer = None
  if self.config.get("enable_epss_scoring"):
      try:
          from epss_scorer import EPSSScorer
          self.epss_scorer = EPSSScorer()
      except ImportError:
          pass
  ```
- **Constraint**: Only modify `__init__`. Don't change `analyze()` or `_enrich_findings()`.

### Agent 7: json-validation
- **New file**: `scripts/schema_validator.py`
- **Change**: Create a lightweight JSON schema validator for external data parsing. Identify the 12+ locations mentioned in audit that parse JSON from untrusted sources. Add validation calls.
- **Constraint**: No external dependencies (use `jsonschema` only if already in requirements.txt, otherwise use simple dict-key validation).

### Agent 8: shared-enrichment
- **New file**: `scripts/enrichment_pipeline.py`
- **Change**: Extract the shared enrichment logic (EPSS, fix versions, VEX, dedup, compliance, suppression) from both `run_ai_audit.py` and `hybrid_analyzer.py` into a single module.
- **Interface**: `run_enrichment_pipeline(findings: list, config: dict) -> list`
- **Constraint**: Both orchestrators must import and use this. Coordinator handles the import changes in orchestrator files after agent creates the module.

### Wave 2 Verification
```bash
ruff check scripts/ && ruff format scripts/
pytest -v --cov=scripts -x
# Manual smoke test of both orchestrators
python scripts/run_ai_audit.py --help
python scripts/hybrid_analyzer.py --help
```

---

## Wave 3 — Tests & Docs

**Branch**: `feat/audit-wave3-tests-docs`
**Agents**: 5 parallel
**Risk**: Low

### Agent 9: test-hybrid-analyzer
- **New file**: `tests/unit/test_hybrid_analyzer.py`
- **Coverage**: `__init__`, `analyze()`, `_enrich_findings()`, lazy loading (if Wave 2 completed)

### Agent 10: test-sandbox-validator
- **New file**: `tests/unit/test_sandbox_validator.py`
- **Coverage**: Core validation flows, Docker isolation checks

### Agent 11: test-supply-chain (extend)
- **File**: `tests/unit/test_supply_chain_analyzer.py` (already exists)
- **Coverage**: Verify existing tests, add coverage for subprocess calls

### Agent 12: test-phase1-scanning
- **New file**: `tests/unit/test_phase1_scanning.py`
- **Coverage**: `run_phase1_scanning()` with mocked scanners

### Agent 13: arch-diagrams
- **New files**: `docs/architecture/pipeline-flow.md`, `docs/architecture/module-dependencies.md`
- **Content**: Mermaid diagrams showing 6-phase pipeline flow and module dependency graph

### Wave 3 Verification
```bash
pytest -v --cov=scripts
# Check new test files pass independently
pytest tests/unit/test_hybrid_analyzer.py -v
pytest tests/unit/test_sandbox_validator.py -v
pytest tests/unit/test_phase1_scanning.py -v
```

---

## File Ownership Rules

- Each agent owns specific files — NO shared file edits by agents
- Coordinator handles all merge operations and shared file updates
- If agent needs change in another agent's file, it reports back

## Out of Scope

- Item #10: Dependency injection (skipped per user decision)
- Modules that already have test files
- Rego policy files
- GitHub Action workflows
