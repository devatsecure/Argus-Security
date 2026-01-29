# Deep Analysis Safety Controls - Quick Reference

## 🚀 Quick Start

```bash
# Enable with defaults (recommended for first-time use)
python scripts/run_ai_audit.py . --enable-deep-analysis

# Defaults:
# - Max files: 50
# - Timeout: 300s (5 min)
# - Cost ceiling: $5.00
```

---

## 📋 All Safety Flags

| Flag | Default | Purpose |
|------|---------|---------|
| `--max-files-deep-analysis=N` | 50 | Limit files analyzed |
| `--deep-analysis-timeout=N` | 300 | Timeout in seconds |
| `--deep-analysis-cost-ceiling=N` | 5.0 | Max USD spend |
| `--deep-analysis-mode` | off | Analysis mode |
| `--deep-analysis-dry-run` | false | Estimate cost only |

---

## 🎯 Common Scenarios

### Scenario 1: PR Review (Fast)
```bash
python scripts/run_ai_audit.py . \
  --deep-analysis-mode=semantic-only \
  --max-files-deep-analysis=20 \
  --deep-analysis-timeout=120 \
  --deep-analysis-cost-ceiling=0.50
```
**Cost:** ~$0.30 | **Time:** ~2 min

### Scenario 2: CI/CD Pipeline
```bash
python scripts/run_ai_audit.py . \
  --deep-analysis-mode=conservative \
  --max-files-deep-analysis=25 \
  --deep-analysis-timeout=180 \
  --deep-analysis-cost-ceiling=1.0
```
**Cost:** ~$0.75 | **Time:** ~3 min

### Scenario 3: Nightly Security Scan
```bash
python scripts/run_ai_audit.py . \
  --deep-analysis-mode=conservative \
  --max-files-deep-analysis=100 \
  --deep-analysis-timeout=900 \
  --deep-analysis-cost-ceiling=10.0
```
**Cost:** ~$7.00 | **Time:** ~15 min

### Scenario 4: Pre-Release Audit
```bash
python scripts/run_ai_audit.py . \
  --deep-analysis-mode=full \
  --max-files-deep-analysis=200 \
  --deep-analysis-timeout=1800 \
  --deep-analysis-cost-ceiling=25.0
```
**Cost:** ~$20.00 | **Time:** ~30 min

---

## ⚠️ What Happens When Limits Hit

| Limit | Behavior | Output |
|-------|----------|--------|
| **File Count** | Truncates list, warns | `⚠️ Limiting to 50 files (237 requested)` |
| **Timeout** | Aborts gracefully | `⏰ TIMEOUT: Analysis exceeded 300s` |
| **Cost (80%)** | Warning only | `⚠️ COST WARNING: $4.12 / $5.00 (82%)` |
| **Cost (100%)** | Hard stop | `💰 COST CEILING REACHED: $5.01 >= $5.00` |

**All cases return partial results!**

---

## 🧪 Test Before Running

```bash
# Always dry-run first to estimate cost
python scripts/run_ai_audit.py . \
  --enable-deep-analysis \
  --deep-analysis-dry-run
```

Output:
```
🔍 DRY RUN - Estimated cost: $3.45
   Files: 50/237
   Time: ~450s
```

---

## 🔧 Adjust Limits On-The-Fly

### Problem: "Too slow"
```bash
# Solution: Reduce files or timeout
--max-files-deep-analysis=25
--deep-analysis-timeout=180
```

### Problem: "Too expensive"
```bash
# Solution 1: Lower ceiling
--deep-analysis-cost-ceiling=2.0

# Solution 2: Lighter mode
--deep-analysis-mode=semantic-only

# Solution 3: Fewer files
--max-files-deep-analysis=25
```

---

## 📊 Monitoring

Enable debug logging to see real-time cost tracking:
```bash
export DEEP_ANALYSIS_LOG_LEVEL=DEBUG
python scripts/run_ai_audit.py . --enable-deep-analysis
```

Output:
```
DEBUG: 💰 Cost: +$0.0234 → $0.0234 (semantic)
DEBUG: 💰 Cost: +$0.0187 → $0.0421 (semantic)
WARNING: ⚠️ COST WARNING: Approaching ceiling ($4.12 / $5.00 = 82%)
```

---

## 🌍 Environment Variables

Set defaults for your team:
```bash
export DEEP_ANALYSIS_MODE=conservative
export DEEP_ANALYSIS_MAX_FILES=50
export DEEP_ANALYSIS_TIMEOUT=300
export DEEP_ANALYSIS_COST_CEILING=5.0
```

Then simply:
```bash
python scripts/run_ai_audit.py . --enable-deep-analysis
```

---

## ✅ Verify Implementation

```bash
# Test all safety controls
python scripts/test_deep_analysis_safety.py

# Expected: ✓ Passed: 5/5
```

---

## 📚 Full Documentation

- **Full Guide:** `DEEP_ANALYSIS_SAFETY_CONTROLS.md` (400+ lines)
- **Examples:** `DEEP_ANALYSIS_EXAMPLES.md` (command templates)
- **Tests:** `scripts/test_deep_analysis_safety.py`

---

## 🆘 Quick Troubleshooting

| Error | Fix |
|-------|-----|
| "Estimated cost exceeds ceiling" | Increase `--deep-analysis-cost-ceiling` OR reduce `--max-files-deep-analysis` |
| "Analysis aborted: timeout" | Increase `--deep-analysis-timeout` OR reduce `--max-files-deep-analysis` |
| "Analysis aborted: cost_ceiling" | Increase `--deep-analysis-cost-ceiling` OR use `--deep-analysis-mode=semantic-only` |

---

**Remember:** All limits are configurable. Start conservative, increase as needed!
