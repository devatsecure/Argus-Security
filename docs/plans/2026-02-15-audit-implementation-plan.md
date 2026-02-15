# Audit Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement 10 of 12 code audit action items across 3 sequential waves (quick wins, refactoring, tests+docs), improving code health from C+ to B+.

**Architecture:** Sequential wave execution — Wave 1 (quick wins) merges to main, then Wave 2 (refactoring) builds on it, then Wave 3 (tests+docs). Each wave uses parallel agents with strict file ownership. Coordinator handles all cross-file integration.

**Tech Stack:** Python 3.9+, pytest, ruff, mermaid diagrams

---

## Corrected Scope (post-exploration)

| Audit Item | Status | Notes |
|------------|--------|-------|
| #1 Bare except | DO | 5 instances across 3 files |
| #2 Temp file cleanup | SKIP | All 4 already have finally blocks |
| #3 Duplicate _detect_frameworks | DO | Lines 186-268 is dead code (shadowed) |
| #4 Env var sanitization | DO | hybrid/cli.py:233-240 |
| #5 Extract run_audit() | DO | 989 lines → phase functions |
| #6 Lazy-load __init__ | DO | hybrid_analyzer.py:206-588 |
| #7 Tests for untested modules | DO | Wave 3 |
| #8 JSON schema validation | DO | New module |
| #9 Shared enrichment pipeline | DO | Extract from both orchestrators |
| #10 Dependency injection | SKIP | User decision |
| #11 Test coverage | DO | Merged with #7 |
| #12 Architecture diagrams | DO | Mermaid in docs/ |

---

## Wave 1: Quick Wins

**Branch:** `feat/audit-wave1-quickwins`

### Task 1: Fix bare except clauses

**Files:**
- Modify: `scripts/dashboard/observability_dashboard.py:286,311`
- Modify: `scripts/feedback_loop.py:356`
- Modify: `scripts/sandbox_integration.py:472`

**Step 1: Fix observability_dashboard.py bare excepts**

Both bare excepts at lines 286 and 311 are parsing `datetime.fromisoformat()` — catch `ValueError`:

```python
# Line 286 — replace:
            except:
# with:
            except (ValueError, TypeError):

# Line 311 — replace:
            except:
# with:
            except (ValueError, TypeError):
```

**Step 2: Fix feedback_loop.py bare except**

Line 356 is loading a JSON file — catch file/JSON errors:

```python
# Line 356 — replace:
        except:
# with:
        except (OSError, json.JSONDecodeError, KeyError):
```

**Step 3: Fix sandbox_integration.py bare except**

Line 472 is a urllib network call — catch network errors:

```python
# Line 472 — replace:
    except:
# with:
    except (OSError, urllib.error.URLError):
```

**Step 4: Run verification**

Run: `ruff check scripts/dashboard/observability_dashboard.py scripts/feedback_loop.py scripts/sandbox_integration.py`
Expected: No errors

Run: `pytest tests/ -x -q --tb=short 2>&1 | tail -5`
Expected: All tests pass

**Step 5: Commit**

```bash
git add scripts/dashboard/observability_dashboard.py scripts/feedback_loop.py scripts/sandbox_integration.py
git commit -m "fix: replace bare except clauses with specific exception types (3 files)"
```

---

### Task 2: Remove duplicate _detect_frameworks

**Files:**
- Modify: `scripts/threat_model_generator.py:186-268`

**Step 1: Verify which definition is active**

In Python, when a class has two methods with the same name, the LAST definition wins. So:
- Lines 186-268: DEAD CODE (shadowed by second definition)
- Lines 668-746: ACTIVE (this is what Python uses)

Both are identical. Delete lines 186-268 (the dead first definition).

**Step 2: Delete the dead first definition**

Remove lines 186 through 268 (the entire first `_detect_frameworks` method). The second definition at line 668 (which will shift up) remains as the sole implementation.

**Step 3: Run verification**

Run: `ruff check scripts/threat_model_generator.py`
Expected: No errors

Run: `pytest tests/unit/test_threat_model.py -v 2>&1 | tail -10`
Expected: All tests pass

**Step 4: Commit**

```bash
git add scripts/threat_model_generator.py
git commit -m "refactor: remove duplicate _detect_frameworks method (dead code)"
```

---

### Task 3: Sanitize env vars in hybrid/cli.py

**Files:**
- Modify: `scripts/hybrid/cli.py:232-240`

**Step 1: Add validation before os.environ writes**

```python
# Replace lines 232-240:
    # Disclosure options (set via environment for pipeline use)
    if args.enable_disclosure_report:
        os.environ["ENABLE_DISCLOSURE_REPORT"] = "true"
    if args.disclosure_repo:
        os.environ["DISCLOSURE_REPO_URL"] = args.disclosure_repo
    if args.disclosure_reporter:
        os.environ["DISCLOSURE_REPORTER"] = args.disclosure_reporter
    if args.disclosure_create_discussion:
        os.environ["DISCLOSURE_CREATE_DISCUSSION"] = "true"

# With:
    # Disclosure options (set via environment for pipeline use)
    # Note: downstream modules (disclosure_reporter.py) read from os.environ,
    # so we must set these here. Validate strings to prevent injection.
    if args.enable_disclosure_report:
        os.environ["ENABLE_DISCLOSURE_REPORT"] = "true"
    if args.disclosure_repo:
        # Validate URL format (basic check)
        repo_url = str(args.disclosure_repo).strip()
        if repo_url and repo_url.startswith(("https://", "http://")):
            os.environ["DISCLOSURE_REPO_URL"] = repo_url
        else:
            print(f"⚠️  Invalid disclosure repo URL: {repo_url}")
    if args.disclosure_reporter:
        # Sanitize reporter name (alphanumeric, hyphens, underscores only)
        reporter = str(args.disclosure_reporter).strip()
        if reporter and all(c.isalnum() or c in "-_@." for c in reporter):
            os.environ["DISCLOSURE_REPORTER"] = reporter
        else:
            print(f"⚠️  Invalid disclosure reporter: {reporter}")
    if args.disclosure_create_discussion:
        os.environ["DISCLOSURE_CREATE_DISCUSSION"] = "true"
```

**Step 2: Run verification**

Run: `ruff check scripts/hybrid/cli.py`
Expected: No errors

Run: `pytest tests/test_hybrid_cli.py -v 2>&1 | tail -10`
Expected: All tests pass

**Step 3: Commit**

```bash
git add scripts/hybrid/cli.py
git commit -m "fix: validate env vars before os.environ assignment in hybrid CLI"
```

---

### Task 4: Wave 1 integration verification

**Step 1: Run full test suite**

Run: `pytest tests/ -v --tb=short 2>&1 | tail -20`
Expected: All tests pass

**Step 2: Run linter**

Run: `ruff check scripts/ && echo "OK"`
Expected: OK

---

## Wave 2: Refactoring

**Branch:** `feat/audit-wave2-refactoring`

### Task 5: Extract run_audit() into phase functions

**Files:**
- Modify: `scripts/run_ai_audit.py`

This is the highest-risk task. The 989-line `run_audit()` function (lines 1106-2094) will be decomposed into:

1. `_setup_audit()` — lines 1106-1230 (provider detection, model setup, config)
2. `_run_scanner_phase()` — lines 1235-1331 (heuristics + Semgrep)
3. `_run_phase1_research()` — lines 1529-1628 (LLM research call)
4. `_run_phase2_planning()` — lines 1631-1696 (LLM planning call)
5. `_run_phase2_deep_analysis()` — lines 1699-1798 (deep analysis engine)
6. `_run_phase3_analysis()` — lines 1800-1946 (LLM analysis + finding merge)
7. `_run_reporting()` — lines 1948-2086 (enrichment, SARIF, JSON, GitHub output)

**Step 1: Create an AuditContext dataclass to pass state between phases**

Add above `run_audit()`:

```python
@dataclass
class AuditContext:
    """Shared state passed between audit phases."""
    repo_path: str
    config: dict
    review_type: str
    metrics: ReviewMetrics
    provider: str
    client: Any
    model: str
    max_tokens: int
    circuit_breaker: CostCircuitBreaker
    phase_gate: Optional[Any]
    threat_model: Optional[dict]
    files: list
    context_tracker: Any
    summarizer: Any
```

**Step 2: Extract _setup_audit()**

Extract lines 1109-1230 into `_setup_audit(repo_path, config, review_type)` that returns an `AuditContext`.

**Step 3: Extract _run_scanner_phase()**

Extract lines 1235-1331 into `_run_scanner_phase(ctx: AuditContext)` that returns `(heuristic_results, semgrep_results)`.

**Step 4: Extract _run_phase1_research()**

Extract lines 1529-1628 into `_run_phase1_research(ctx, files)` that returns `research_data`.

**Step 5: Extract _run_phase2_planning()**

Extract lines 1631-1696 into `_run_phase2_planning(ctx, research_data, priority_files)` that returns `plan_summary`.

**Step 6: Extract _run_phase2_deep_analysis()**

Extract lines 1699-1798 into `_run_phase2_deep_analysis(ctx, findings)` that returns `(deep_analysis_findings, findings_dict)`.

**Step 7: Extract _run_phase3_analysis()**

Extract lines 1800-1946 into `_run_phase3_analysis(ctx, plan_summary, priority_files, findings_dict)` that returns `findings`.

**Step 8: Extract _run_reporting()**

Extract lines 1948-2086 into `_run_reporting(ctx, findings, report, report_file)` that returns `(blocker_count, suggestion_count)`.

**Step 9: Rewrite run_audit() as thin orchestrator**

```python
def run_audit(repo_path, config, review_type="audit"):
    """Run AI-powered code audit with multi-LLM support"""
    ctx = _setup_audit(repo_path, config, review_type)
    heuristic_results, semgrep_results = _run_scanner_phase(ctx)

    # Multi-agent mode branches here (unchanged)
    multi_agent_mode = config.get("multi_agent_mode", "single")
    if multi_agent_mode == "sequential":
        # ... existing multi-agent code (unchanged) ...
        return blocker_count, suggestion_count, ctx.metrics

    # Single-agent 3-phase process
    print("🤖 Mode: Single-Agent (3-Phase Process)")
    research_data = _run_phase1_research(ctx)
    priority_files = [f for f in ctx.files if f['path'] in research_data.get('high_priority_files', [])]
    if not priority_files:
        priority_files = ctx.files[:10]

    plan_summary = _run_phase2_planning(ctx, research_data, priority_files)
    deep_findings, findings_dict = _run_phase2_deep_analysis(ctx, {})
    findings = _run_phase3_analysis(ctx, plan_summary, priority_files, findings_dict)
    return _run_reporting(ctx, findings)
```

**Step 10: Run verification**

Run: `pytest tests/test_run_ai_audit.py -v 2>&1 | tail -20`
Expected: All tests pass

Run: `python scripts/run_ai_audit.py --help`
Expected: Help text prints (verifies imports work)

**Step 11: Commit**

```bash
git add scripts/run_ai_audit.py
git commit -m "refactor: extract run_audit() into phase functions (CC 103 → ~15 per function)"
```

---

### Task 6: Lazy-load modules in hybrid_analyzer.__init__

**Files:**
- Modify: `scripts/hybrid_analyzer.py:317-588`

**Step 1: Add config guard to AI client initialization**

The AI client block (lines 318-333) already checks `self.enable_ai_enrichment`. But subsequent blocks like multi-agent (336), spontaneous discovery (348), IRIS (360), collaborative reasoning (373) should also check config dict:

```python
# Add config-level guard to each block. Example for lines 398-406:
# Before:
        if self.enable_semgrep:
# After (add config check):
        if self.enable_semgrep and self.config.get("enable_semgrep", True):
```

However, `self.enable_semgrep` is already set from the constructor arg which comes from CLI/config. The actual lazy-load improvement is: **skip the import + instantiation entirely when the feature is disabled**.

**Step 2: Review current code**

Current code already uses `if self.enable_X:` guards before each try/import block (lines 398-588). This IS lazy loading — imports only happen when the feature is enabled.

**Step 3: Consolidate the validation check**

The validation block (lines 564-588) checks all 14 boolean flags individually. Replace with:

```python
        # Validation: At least one scanner or AI enrichment must be enabled
        enabled_scanners = [
            attr for attr in dir(self)
            if attr.startswith("enable_") and getattr(self, attr, False)
        ]
        if not enabled_scanners:
            raise ValueError(
                "❌ ERROR: At least one tool must be enabled!\n"
                "   Use --help to see available scanner flags."
            )
```

**Step 4: Run verification**

Run: `pytest tests/ -x -q --tb=short 2>&1 | tail -5`
Expected: All tests pass

**Step 5: Commit**

```bash
git add scripts/hybrid_analyzer.py
git commit -m "refactor: consolidate scanner validation in hybrid_analyzer.__init__"
```

---

### Task 7: Create shared enrichment pipeline module

**Files:**
- Create: `scripts/enrichment_pipeline.py`
- Modify: `scripts/run_ai_audit.py` (replace `_run_enrichment_pipeline`)
- Modify: `scripts/hybrid_analyzer.py` (replace `_enrich_findings`)

**Step 1: Create enrichment_pipeline.py**

Extract the shared enrichment logic. Both orchestrators run the same 6-step pipeline:
1. EPSS scoring
2. Fix version tracking
3. VEX filtering
4. Deduplication
5. Compliance mapping
6. Advanced suppression

```python
"""Shared vulnerability enrichment pipeline.

Used by both run_ai_audit.py and hybrid_analyzer.py to avoid
duplicating the EPSS → Fix Versions → VEX → Dedup → Compliance → Suppression chain.
"""
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# Lazy feature availability checks
def _check_available(module_name):
    try:
        __import__(module_name)
        return True
    except ImportError:
        return False

def run_enrichment_pipeline(findings, config, target_path, *, as_dicts=True):
    """Run the 6-step enrichment pipeline on findings.

    Args:
        findings: List of finding dicts or dataclass instances.
        config: Configuration dict with enable_* keys.
        target_path: Repository path for cache directories.
        as_dicts: If True, return dicts. If False, return unchanged type.

    Returns:
        (enriched_findings, metadata) tuple.
    """
    if not findings:
        return findings, {}

    metadata = {}
    remaining = list(findings)

    # Step 1: EPSS
    if _check_available("epss_scorer") and _parse_bool(config.get("enable_epss_scoring", True)):
        try:
            from epss_scorer import EPSSScorer
            scorer = EPSSScorer(cache_dir=str(Path(target_path) / ".argus-cache"))
            remaining = scorer.enrich_findings(remaining)
            logger.info("EPSS: enriched findings")
        except Exception as e:
            logger.warning("EPSS scoring failed (non-fatal): %s", e)

    # Step 2: Fix versions
    if _check_available("fix_version_tracker") and _parse_bool(config.get("enable_fix_version_tracking", True)):
        try:
            from fix_version_tracker import FixVersionTracker
            tracker = FixVersionTracker()
            fix_infos = [info for f in remaining if (info := tracker.extract_fix_info(f))]
            if fix_infos:
                remaining = tracker.enrich_findings(remaining, fix_infos)
                metadata["fix_versions"] = tracker.get_summary(fix_infos)
            logger.info("Fix versions: %d found", len(fix_infos))
        except Exception as e:
            logger.warning("Fix version tracking failed (non-fatal): %s", e)

    # Step 3: VEX
    if _check_available("vex_processor") and _parse_bool(config.get("enable_vex", True)):
        try:
            from vex_processor import VEXProcessor
            processor = VEXProcessor(auto_discover_dir=str(Path(target_path) / ".argus/vex"))
            statements = processor.load_statements()
            if statements:
                remaining, suppressed = processor.filter_findings(remaining, statements)
                metadata["vex_suppressed"] = len(suppressed)
                logger.info("VEX: %d suppressed", len(suppressed))
        except Exception as e:
            logger.warning("VEX processing failed (non-fatal): %s", e)

    # Step 4: Dedup
    if _check_available("vuln_deduplicator") and _parse_bool(config.get("enable_vuln_deduplication", True)):
        try:
            from vuln_deduplicator import VulnDeduplicator
            strategy = config.get("deduplication_strategy", "auto")
            deduplicator = VulnDeduplicator(strategy=strategy)
            result = deduplicator.deduplicate(remaining)
            remaining = result.kept_findings
            logger.info("Dedup: %d remaining", len(remaining))
        except Exception as e:
            logger.warning("Deduplication failed (non-fatal): %s", e)

    # Step 5: Compliance mapping
    if _check_available("compliance_mapper") and _parse_bool(config.get("enable_compliance_mapping", True)):
        try:
            from compliance_mapper import ComplianceMapper
            frameworks_str = config.get("compliance_frameworks", "")
            frameworks = [f.strip() for f in frameworks_str.split(",") if f.strip()] if frameworks_str else None
            mapper = ComplianceMapper(frameworks=frameworks)
            mappings = mapper.map_findings(remaining)
            if mappings:
                metadata["compliance_controls"] = len(mappings)
                logger.info("Compliance: %d controls mapped", len(mappings))
        except Exception as e:
            logger.warning("Compliance mapping failed (non-fatal): %s", e)

    # Step 6: Advanced suppression
    if _check_available("advanced_suppression") and _parse_bool(config.get("enable_advanced_suppression", True)):
        try:
            from advanced_suppression import AdvancedSuppressionManager
            ignore_path = Path(target_path) / ".argus-ignore.yml"
            suppressor = AdvancedSuppressionManager(
                config_path=str(ignore_path),
                auto_expire_days=config.get("suppression_auto_expire_days", 90),
            )
            suppressor.load_rules()
            remaining, suppressed = suppressor.filter_findings(remaining)
            if suppressed:
                metadata["suppressed"] = len(suppressed)
                logger.info("Suppression: %d filtered", len(suppressed))
        except Exception as e:
            logger.warning("Suppression failed (non-fatal): %s", e)

    return remaining, metadata


def _parse_bool(value):
    if isinstance(value, str):
        return value.lower() == "true"
    return bool(value)
```

**Step 2: Wire into run_ai_audit.py**

Replace `_run_enrichment_pipeline()` (lines 870-1004) with a call to the shared module:

```python
from enrichment_pipeline import run_enrichment_pipeline as _shared_enrichment

def _run_enrichment_pipeline(findings, config, repo_path, metrics=None):
    return _shared_enrichment(findings, config, repo_path)
```

**Step 3: Wire into hybrid_analyzer.py**

Replace `_enrich_findings()` internals (lines 805-933) with a call to the shared module. Keep the HybridFinding ↔ dict conversion wrapper.

**Step 4: Run verification**

Run: `pytest tests/ -x -q --tb=short 2>&1 | tail -5`
Expected: All tests pass

Run: `python scripts/run_ai_audit.py --help && python scripts/hybrid_analyzer.py --help`
Expected: Both print help text

**Step 5: Commit**

```bash
git add scripts/enrichment_pipeline.py scripts/run_ai_audit.py scripts/hybrid_analyzer.py
git commit -m "refactor: extract shared enrichment pipeline from both orchestrators"
```

---

### Task 8: Add JSON schema validation for external data

**Files:**
- Create: `scripts/schema_validator.py`

**Step 1: Create lightweight validator**

```python
"""Lightweight JSON schema validation for untrusted external data.

Validates structure of JSON from external sources (LLM responses, API data,
scanner output) without requiring jsonschema dependency.
"""
import logging
from typing import Any

logger = logging.getLogger(__name__)


class ValidationError(Exception):
    """Raised when data fails schema validation."""
    pass


def validate_finding(data: dict) -> dict:
    """Validate a security finding dict has required fields."""
    required = {"severity", "message"}
    missing = required - set(data.keys())
    if missing:
        raise ValidationError(f"Finding missing required fields: {missing}")
    valid_severities = {"critical", "high", "medium", "low", "info", "unknown"}
    if data.get("severity", "").lower() not in valid_severities:
        logger.warning("Unknown severity: %s, defaulting to 'medium'", data.get("severity"))
        data["severity"] = "medium"
    return data


def validate_scanner_output(data: dict, scanner_name: str) -> dict:
    """Validate scanner output has expected structure."""
    if not isinstance(data, dict):
        raise ValidationError(f"{scanner_name} output must be a dict, got {type(data).__name__}")
    if "findings" in data and not isinstance(data["findings"], list):
        raise ValidationError(f"{scanner_name} findings must be a list")
    return data


def validate_llm_response(data: Any, expected_keys: set[str] | None = None) -> dict:
    """Validate parsed LLM JSON response."""
    if not isinstance(data, dict):
        raise ValidationError(f"LLM response must be a dict, got {type(data).__name__}")
    if expected_keys:
        missing = expected_keys - set(data.keys())
        if missing:
            logger.warning("LLM response missing expected keys: %s", missing)
    return data
```

**Step 2: Run verification**

Run: `ruff check scripts/schema_validator.py`
Expected: No errors

**Step 3: Commit**

```bash
git add scripts/schema_validator.py
git commit -m "feat: add lightweight JSON schema validator for external data"
```

---

### Task 9: Wave 2 integration verification

**Step 1: Full test suite**

Run: `pytest tests/ -v --tb=short 2>&1 | tail -30`
Expected: All pass

**Step 2: Lint check**

Run: `ruff check scripts/ && echo "OK"`
Expected: OK

**Step 3: Smoke test orchestrators**

Run: `python scripts/run_ai_audit.py --help`
Run: `python -c "from scripts.hybrid_analyzer import HybridSecurityAnalyzer; print('OK')"`
Expected: Both succeed

---

## Wave 3: Tests & Documentation

**Branch:** `feat/audit-wave3-tests-docs`

### Task 10: Tests for hybrid_analyzer.py

**Files:**
- Create: `tests/unit/test_hybrid_analyzer_core.py`

**Step 1: Write tests for __init__ with various feature flags**

```python
"""Tests for hybrid_analyzer.py core functionality."""
import pytest
from unittest.mock import patch, MagicMock

# Mock all scanner imports before importing the module
@pytest.fixture
def analyzer_minimal():
    """Create analyzer with all scanners disabled."""
    with patch.dict("sys.modules", {
        "semgrep_scanner": MagicMock(),
        "trivy_scanner": MagicMock(),
    }):
        from hybrid_analyzer import HybridSecurityAnalyzer
        return HybridSecurityAnalyzer(
            enable_semgrep=False,
            enable_trivy=False,
            enable_checkov=False,
            enable_ai_enrichment=True,  # Need at least one
            enable_dast=False,
            enable_supply_chain=False,
            enable_fuzzing=False,
            enable_threat_intel=False,
            enable_remediation=False,
            enable_runtime_security=False,
            enable_regression_testing=False,
        )

def test_init_all_disabled_raises():
    """All scanners disabled should raise ValueError."""
    from hybrid_analyzer import HybridSecurityAnalyzer
    with pytest.raises(ValueError, match="At least one tool"):
        HybridSecurityAnalyzer(
            enable_semgrep=False, enable_trivy=False, enable_checkov=False,
            enable_api_security=False, enable_dast=False, enable_supply_chain=False,
            enable_fuzzing=False, enable_threat_intel=False, enable_remediation=False,
            enable_runtime_security=False, enable_regression_testing=False,
            enable_ai_enrichment=False, enable_nuclei_templates=False,
            enable_zap_baseline=False,
        )

def test_init_scanner_import_failure_disables_gracefully():
    """Scanner that fails to import should be disabled, not crash."""
    with patch.dict("sys.modules", {"semgrep_scanner": None}):
        from hybrid_analyzer import HybridSecurityAnalyzer
        analyzer = HybridSecurityAnalyzer(
            enable_semgrep=True,
            enable_ai_enrichment=True,
        )
        assert analyzer.enable_semgrep is False  # Gracefully disabled
```

**Step 2: Write tests for _enrich_findings()**

Test that enrichment pipeline runs without errors when modules are available/unavailable.

**Step 3: Run tests**

Run: `pytest tests/unit/test_hybrid_analyzer_core.py -v`
Expected: All pass

**Step 4: Commit**

```bash
git add tests/unit/test_hybrid_analyzer_core.py
git commit -m "test: add unit tests for hybrid_analyzer core initialization and enrichment"
```

---

### Task 11: Tests for sandbox_validator.py

**Files:**
- Create: `tests/unit/test_sandbox_validator_core.py`

**Step 1: Write tests for core validation logic**

Test initialization, finding validation, Docker sandbox interaction (mocked).

**Step 2: Run tests**

Run: `pytest tests/unit/test_sandbox_validator_core.py -v`
Expected: All pass

**Step 3: Commit**

```bash
git add tests/unit/test_sandbox_validator_core.py
git commit -m "test: add unit tests for sandbox_validator core flows"
```

---

### Task 12: Tests for phase1_scanning

**Files:**
- Create: `tests/unit/test_phase1_scanning_core.py`

**Step 1: Write tests with mocked scanners**

Test `run_phase1_scanning()` with Semgrep/Trivy/Checkov mocked to return known findings.

**Step 2: Run tests**

Run: `pytest tests/unit/test_phase1_scanning_core.py -v`
Expected: All pass

**Step 3: Commit**

```bash
git add tests/unit/test_phase1_scanning_core.py
git commit -m "test: add unit tests for phase1_scanning with mocked scanners"
```

---

### Task 13: Architecture diagrams

**Files:**
- Create: `docs/architecture/pipeline-flow.md`
- Create: `docs/architecture/module-dependencies.md`

**Step 1: Create pipeline flow diagram**

Mermaid diagram showing the 6-phase pipeline from scanner input to SARIF output.

**Step 2: Create module dependency diagram**

Mermaid diagram showing how hybrid_analyzer.py and run_ai_audit.py relate to the ~50 integrated modules.

**Step 3: Commit**

```bash
git add docs/architecture/
git commit -m "docs: add architecture diagrams for pipeline flow and module dependencies"
```

---

### Task 14: Wave 3 integration verification

**Step 1: Full test suite**

Run: `pytest tests/ -v --tb=short 2>&1 | tail -30`
Expected: All pass including new tests

**Step 2: Verify new test files independently**

Run: `pytest tests/unit/test_hybrid_analyzer_core.py tests/unit/test_sandbox_validator_core.py tests/unit/test_phase1_scanning_core.py -v`
Expected: All pass

---

## Agent Ownership Matrix

| Agent Name | Owned Files | Wave |
|------------|------------|------|
| fix-bare-except | observability_dashboard.py, feedback_loop.py, sandbox_integration.py | 1 |
| fix-duplicate | threat_model_generator.py | 1 |
| fix-env-vars | hybrid/cli.py | 1 |
| extract-run-audit | run_ai_audit.py | 2 |
| lazy-load-init | hybrid_analyzer.py (only __init__ validation block) | 2 |
| shared-enrichment | enrichment_pipeline.py (NEW), run_ai_audit.py*, hybrid_analyzer.py* | 2 |
| json-validation | schema_validator.py (NEW) | 2 |
| test-hybrid | tests/unit/test_hybrid_analyzer_core.py (NEW) | 3 |
| test-sandbox | tests/unit/test_sandbox_validator_core.py (NEW) | 3 |
| test-phase1 | tests/unit/test_phase1_scanning_core.py (NEW) | 3 |
| arch-diagrams | docs/architecture/*.md (NEW) | 3 |

*Coordinator handles cross-file wiring for shared-enrichment into both orchestrators.

## Risk Mitigations

1. **Task 5 (extract run_audit)** is highest risk — do this FIRST in Wave 2, verify thoroughly before other Wave 2 tasks
2. **Task 7 (shared enrichment)** modifies both orchestrators — coordinator must apply changes sequentially after the new module is created
3. All agents run `ruff check` and `pytest` before committing
4. Each wave gets its own branch; merge only after full verification
