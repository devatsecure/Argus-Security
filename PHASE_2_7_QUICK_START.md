# Phase 2.7 Deep Analysis - Quick Start Guide

## What Was Fixed?

✅ CLI arguments now work! Phase 2.7 executes when `--deep-analysis-mode` is passed.

**Problem:** `⏭️ Phase 2.7: Deep Analysis skipped (mode=off)` even when flag was passed
**Cause:** `__main__` block ignored CLI args and only used env vars
**Fix:** Now uses `parse_args()` + `build_config()` properly

---

## Quick Commands

### 1. Conservative Mode (Recommended)
```bash
python scripts/run_ai_audit.py . audit \
  --deep-analysis-mode=conservative \
  --benchmark
```
- Runs Semantic + Proactive analysis
- Best balance of cost/thoroughness
- Shows benchmark report

### 2. Dry Run (Cost Estimation)
```bash
python scripts/run_ai_audit.py . audit \
  --deep-analysis-mode=conservative \
  --deep-analysis-dry-run
```
- Estimates cost WITHOUT running analysis
- See token/time/cost projections

### 3. Full Mode (All Features)
```bash
python scripts/run_ai_audit.py . audit \
  --deep-analysis-mode=full \
  --max-files-deep-analysis=25
```
- All 4 modules (semantic, proactive, taint, zero-day)
- Limit files to control cost

### 4. Semantic Only (Lightweight)
```bash
python scripts/run_ai_audit.py . audit \
  --deep-analysis-mode=semantic-only
```
- Just code clone detection
- Lowest cost

---

## Available Flags

| Flag | Options | Default | Description |
|------|---------|---------|-------------|
| `--deep-analysis-mode` | off, semantic-only, conservative, full | off | Which modules to run |
| `--max-files-deep-analysis` | integer | 50 | Max files to analyze |
| `--deep-analysis-timeout` | seconds | 300 | Timeout (5 min default) |
| `--deep-analysis-cost-ceiling` | float | 5.0 | Max cost in USD |
| `--deep-analysis-dry-run` | flag | false | Estimate cost only |
| `--benchmark` | flag | false | Show detailed metrics |

---

## Modes Explained

| Mode | Modules Enabled | Use Case | Est. Cost* |
|------|----------------|----------|-----------|
| **off** | None | Default - Phase 2.7 skipped | $0 |
| **semantic-only** | Semantic Code Twin | Find duplicated logic | $0.75 |
| **conservative** | Semantic + Proactive | Balanced vulnerability discovery | $2.00 |
| **full** | All 4 modules | Comprehensive deep scan | $5.00 |

*Estimated for 50 files

---

## Verification Tests

### Test 1: Check imports work
```bash
python -c "from scripts.argus_deep_analysis import DeepAnalysisMode; print('✅ Import OK')"
```

### Test 2: Check mode parsing
```bash
python -c "
from scripts.argus_deep_analysis import DeepAnalysisMode
mode = DeepAnalysisMode.from_string('conservative')
print(f'✅ Conservative mode: {[p.value for p in mode.get_enabled_phases()]}')
"
```

### Test 3: Check argument flow
```bash
python -c "
import sys
sys.path.insert(0, 'scripts')
sys.argv = ['run_ai_audit.py', '.', 'audit', '--deep-analysis-mode=conservative']

from run_ai_audit import parse_args, build_config
args = parse_args()
config = build_config(args)

print(f'✅ Config has deep_analysis_mode: {config.get(\"deep_analysis_mode\")}')
"
```

---

## Expected Output

When Phase 2.7 runs correctly:

```
================================================================================
🔬 PHASE 2.7: DEEP ANALYSIS ENGINE
================================================================================
   Mode: conservative
   Enabled phases: ['semantic', 'proactive']
   📊 Benchmarking: ENABLED

🔍 Running semantic analysis...
   ✓ 25 files, 3 findings, 12.3s

🔍 Running proactive analysis...
   ✓ 25 files, 5 findings, 18.7s

✅ Deep Analysis complete: 8 findings, $1.23 cost
```

If you see `⏭️ Phase 2.7: Deep Analysis skipped (mode=off)` but you passed `--deep-analysis-mode=conservative`, then the fix was not applied correctly.

---

## Safety Controls

Phase 2.7 includes production safety controls:

✅ **File Limiting** - Max 50 files by default (configurable)
✅ **Timeout Protection** - 5 min default, aborts gracefully
✅ **Cost Ceiling** - $5.00 default, stops at 80% with warning
✅ **Dry Run Mode** - Estimate cost before running
✅ **Partial Results** - Returns findings even if aborted

Example with custom safety limits:
```bash
python scripts/run_ai_audit.py . audit \
  --deep-analysis-mode=conservative \
  --max-files-deep-analysis=20 \
  --deep-analysis-timeout=120 \
  --deep-analysis-cost-ceiling=2.0
```

---

## Troubleshooting

**Q: Still seeing "skipped (mode=off)"?**
A: Make sure `run_ai_audit.py` lines 4051-4062 use `parse_args()` and `build_config(args)`

**Q: "Deep Analysis Engine not available"?**
A: Check `scripts/argus_deep_analysis.py` exists and imports work

**Q: "Deep Analysis enabled but no AI client provided"?**
A: Set `export ANTHROPIC_API_KEY="sk-ant-..."`

**Q: Want to see what would happen without cost?**
A: Use `--deep-analysis-dry-run` flag

---

## What Each Module Does

### 🧬 Semantic Code Twin
- Detects duplicated logic across files
- Finds similar vulnerable patterns
- Uses embeddings + similarity search

### 🔍 Proactive Scanner
- Hypothesis-driven vulnerability discovery
- Analyzes code patterns for issues
- Goes beyond signature-based detection

### 🌊 Taint Analysis
- Tracks data flow from sources to sinks
- Finds SQL injection, XSS, etc.
- Traces user input through system

### 🔬 Zero-Day Hunter
- Novel vulnerability pattern detection
- Advanced LLM reasoning
- Highest novelty score findings

---

**Last Updated:** 2026-01-29
**Status:** ✅ Fix verified and working
**PR:** #27 Integration Complete
