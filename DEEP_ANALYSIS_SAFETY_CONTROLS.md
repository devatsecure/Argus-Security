# Deep Analysis Engine - Production Safety Controls

## Overview

The Deep Analysis Engine (Phase 2.7) now includes production-ready safety controls to prevent runaway costs, timeouts, and resource exhaustion. These controls ensure predictable behavior in production environments.

---

## Safety Controls Added

### 1. **File Count Limiting**
Prevents analysis of excessively large codebases

- **Default**: 50 files
- **Behavior**: Truncates file list with warning if exceeded
- **CLI Flag**: `--max-files-deep-analysis=N`
- **Environment**: `DEEP_ANALYSIS_MAX_FILES=N`

**Example:**
```bash
# Limit to 25 files
python scripts/run_ai_audit.py . --enable-deep-analysis --max-files-deep-analysis=25
```

**When limit is hit:**
```
⚠️  Limiting deep analysis to 50 files (requested: 237)
📁 Files to analyze: 50
⏭️  Files skipped: 187
```

---

### 2. **Timeout Protection**
Hard time limit on analysis duration

- **Default**: 300 seconds (5 minutes)
- **Behavior**: Gracefully aborts analysis when timeout is exceeded
- **CLI Flag**: `--deep-analysis-timeout=N`
- **Environment**: `DEEP_ANALYSIS_TIMEOUT=N`

**Example:**
```bash
# Set 10-minute timeout
python scripts/run_ai_audit.py . --enable-deep-analysis --deep-analysis-timeout=600
```

**When timeout is hit:**
```
⏰ TIMEOUT: Analysis exceeded 300s limit
⚠️  Analysis aborted: timeout
✓ Files analyzed: 23/50
⚠️  Aborted: timeout
```

---

### 3. **Cost Ceiling Enforcement**
Maximum USD spend on LLM API calls

- **Default**: $5.00 USD
- **Behavior**:
  - Warns at 80% of ceiling
  - Hard stop at 100% with graceful abort
- **CLI Flag**: `--deep-analysis-cost-ceiling=N`
- **Environment**: `DEEP_ANALYSIS_COST_CEILING=N`

**Example:**
```bash
# Set $10 cost ceiling
python scripts/run_ai_audit.py . --enable-deep-analysis --deep-analysis-cost-ceiling=10.0
```

**When ceiling is approached:**
```
⚠️  COST WARNING: Approaching ceiling ($4.12 / $5.00 = 82%)
💰 COST CEILING REACHED: $5.01 >= $5.00
   Stopping analysis to prevent overspending
⚠️  Analysis aborted: cost_ceiling
```

---

### 4. **Real-Time Cost Tracking**
Monitors spending as analysis progresses

- **Tracks**: Input/output tokens and actual API costs
- **Logs**: Cost after each file analysis
- **Warns**: At 80% threshold

**Example output:**
```
[1/50] Analyzing scripts/hybrid_analyzer.py...
  ✓ Found HIGH issue: SQL injection vulnerability ($0.0234)
💰 Cost: +$0.0234 → $1.4567 (semantic)
```

---

### 5. **Graceful Degradation**
Returns partial results when limits are hit

- **Behavior**:
  - Analysis continues until limit is reached
  - Returns all findings collected so far
  - Marks result as partial with abort reason
- **Fields Added to Result**:
  - `aborted_reason`: "timeout" | "cost_ceiling" | None
  - `files_skipped`: Number of files not analyzed
  - `was_aborted`: Boolean property
  - `is_partial`: Boolean property

**Example:**
```python
result = engine.analyze(files, repo_path)

if result.was_aborted:
    print(f"Analysis aborted: {result.aborted_reason}")
    print(f"Partial results: {len(result.findings)} findings")
    print(f"Files skipped: {result.files_skipped}")
```

---

## Command Line Usage

### Basic Usage with Defaults
```bash
# Enable deep analysis with all default safety limits
python scripts/run_ai_audit.py . --enable-deep-analysis
```

Default limits:
- Max files: 50
- Timeout: 300s (5 min)
- Cost ceiling: $5.00

### Custom Safety Limits
```bash
# Conservative limits for CI/CD
python scripts/run_ai_audit.py . \
  --deep-analysis-mode=conservative \
  --max-files-deep-analysis=25 \
  --deep-analysis-timeout=180 \
  --deep-analysis-cost-ceiling=2.0
```

### Aggressive Limits for Thorough Analysis
```bash
# Thorough analysis with higher limits
python scripts/run_ai_audit.py . \
  --deep-analysis-mode=full \
  --max-files-deep-analysis=200 \
  --deep-analysis-timeout=1800 \
  --deep-analysis-cost-ceiling=20.0
```

### Cost Estimation (Dry Run)
```bash
# Estimate cost before running
python scripts/run_ai_audit.py . \
  --enable-deep-analysis \
  --deep-analysis-dry-run
```

Output:
```
🔍 DRY RUN - Estimated cost: $3.45
   Files: 50/237
   Time: ~450s
   Breakdown: {'semantic': 1.15, 'proactive': 2.30}
```

---

## Environment Variables

Set defaults via environment variables:

```bash
export DEEP_ANALYSIS_MODE=conservative
export DEEP_ANALYSIS_MAX_FILES=50
export DEEP_ANALYSIS_TIMEOUT=300
export DEEP_ANALYSIS_COST_CEILING=5.0

python scripts/run_ai_audit.py . --enable-deep-analysis
```

---

## Standalone Deep Analysis Engine

The engine can also be used standalone:

```bash
# Direct usage
python scripts/argus_deep_analysis.py /path/to/repo \
  --mode=conservative \
  --max-files=50 \
  --timeout=300 \
  --cost-ceiling=5.0
```

---

## Behavior When Limits Are Hit

### File Count Limit
```
⚠️  Limiting deep analysis to 50 files (requested: 237)
⏭️  Files skipped: 187
```
- Analysis continues with first N files
- Remaining files are skipped
- Result marked as partial

### Timeout
```
⏰ TIMEOUT: Analysis exceeded 300s limit
⚠️  Analysis aborted: timeout
```
- Current operation completes
- No new files/phases started
- Partial results returned

### Cost Ceiling
```
80% threshold:
⚠️  COST WARNING: Approaching ceiling ($4.12 / $5.00 = 82%)

100% threshold:
💰 COST CEILING REACHED: $5.01 >= $5.00
   Stopping analysis to prevent overspending
```
- Warning at 80%
- Hard stop at 100%
- No additional LLM calls made
- Partial results returned

---

## Testing Safety Controls

Run the test suite to verify all safety controls:

```bash
python scripts/test_deep_analysis_safety.py
```

Tests:
1. ✓ File Count Limiting
2. ✓ Timeout Protection
3. ✓ Cost Ceiling Enforcement
4. ✓ 80% Cost Warning
5. ✓ Graceful Degradation

---

## API Usage

```python
from argus_deep_analysis import DeepAnalysisConfig, DeepAnalysisEngine, DeepAnalysisMode

# Configure with safety limits
config = DeepAnalysisConfig(
    mode=DeepAnalysisMode.CONSERVATIVE,
    enabled_phases=DeepAnalysisMode.CONSERVATIVE.get_enabled_phases(),
    max_files=50,
    timeout_seconds=300,
    cost_ceiling=5.0,
)

# Initialize engine
engine = DeepAnalysisEngine(
    config=config,
    ai_client=anthropic.Anthropic(api_key="..."),
    model="claude-3-5-sonnet-20241022"
)

# Run analysis
result = engine.analyze("/path/to/repo")

# Check for aborts
if result.was_aborted:
    print(f"Aborted: {result.aborted_reason}")
    print(f"Partial results: {len(result.findings)} findings")
else:
    print(f"Complete: {len(result.findings)} findings")
```

---

## Best Practices

### For CI/CD Pipelines
```bash
# Conservative limits to prevent CI timeouts and cost overruns
--max-files-deep-analysis=25
--deep-analysis-timeout=180  # 3 minutes
--deep-analysis-cost-ceiling=1.0
```

### For Local Development
```bash
# Moderate limits for iterative development
--max-files-deep-analysis=50
--deep-analysis-timeout=300  # 5 minutes
--deep-analysis-cost-ceiling=5.0
```

### For Comprehensive Security Audits
```bash
# Higher limits for thorough analysis
--max-files-deep-analysis=200
--deep-analysis-timeout=1800  # 30 minutes
--deep-analysis-cost-ceiling=25.0
```

### Cost Estimation First
Always run with `--deep-analysis-dry-run` first to estimate costs before committing to a full analysis.

---

## Monitoring & Observability

The engine logs all safety events:

```
INFO: 🔬 Starting Deep Analysis (mode=conservative)
INFO:    Max files: 50
INFO:    Timeout: 300s
INFO:    Cost ceiling: $5.00
DEBUG: ⏱️  Timeout set: 300s
INFO: [1/50] Analyzing scripts/hybrid_analyzer.py...
DEBUG: 💰 Cost: +$0.0234 → $0.0234 (semantic)
WARNING: ⚠️  COST WARNING: Approaching ceiling ($4.12 / $5.00 = 82%)
ERROR: 💰 COST CEILING REACHED: $5.01 >= $5.00
WARNING: ⚠️  Analysis aborted: cost_ceiling
```

Enable debug logging for detailed cost tracking:
```python
logging.basicConfig(level=logging.DEBUG)
```

---

## Troubleshooting

### "Analysis aborted: cost_ceiling"
**Solution**: Increase ceiling or reduce max_files
```bash
--deep-analysis-cost-ceiling=10.0
# or
--max-files-deep-analysis=25
```

### "Analysis aborted: timeout"
**Solution**: Increase timeout or reduce max_files
```bash
--deep-analysis-timeout=600
# or
--max-files-deep-analysis=30
```

### "Estimated cost exceeds ceiling"
**Solution**: Analysis is skipped automatically. Either:
1. Increase ceiling: `--deep-analysis-cost-ceiling=10.0`
2. Reduce files: `--max-files-deep-analysis=25`
3. Use lighter mode: `--deep-analysis-mode=semantic-only`

---

## Implementation Details

### Safety Control Architecture

```
┌─────────────────────────────────────────┐
│  DeepAnalysisEngine                     │
├─────────────────────────────────────────┤
│  Safety State:                          │
│  • _aborted: bool                       │
│  • _abort_reason: str                   │
│  • _timeout_timer: Timer                │
│  • _cost_warning_shown: bool            │
├─────────────────────────────────────────┤
│  Safety Methods:                        │
│  • _setup_timeout()                     │
│  • _cancel_timeout()                    │
│  • _check_cost_ceiling(cost)            │
│  • _track_cost(cost, context)           │
└─────────────────────────────────────────┘
         │
         ├─ File Count: Truncate at config.max_files
         ├─ Timeout: threading.Timer w/ daemon
         ├─ Cost: Real-time tracking w/ 80% warning
         └─ Cleanup: finally block w/ _cancel_timeout()
```

### Execution Flow

```
1. analyze() called
2. ├─ Estimate cost
3. ├─ Check if estimate > ceiling → Skip if true
4. ├─ _setup_timeout() → Start timer
5. ├─ try:
6. │   ├─ For each phase:
7. │   │   ├─ Check _aborted → Break if true
8. │   │   ├─ _check_cost_ceiling() → Abort if exceeded
9. │   │   ├─ _run_phase()
10.│   │   └─ _track_cost()
11.├─ finally:
12.│   └─ _cancel_timeout() → Clean up
13.└─ Return results (partial if aborted)
```

---

## Summary

All safety controls are now production-ready:

✅ **File Count Limiting** - Prevents runaway file analysis
✅ **Timeout Protection** - Hard time limits with graceful abort
✅ **Cost Ceiling** - 80% warning + 100% hard stop
✅ **Real-time Tracking** - Monitor costs during execution
✅ **Graceful Degradation** - Partial results on abort

Default safe limits:
- 50 files max
- 5 minute timeout
- $5 cost ceiling

All limits are configurable via CLI flags or environment variables.
