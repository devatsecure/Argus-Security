# 🔬 Argus v4.1.0 Benchmark Guide

**Purpose:** Validate production readiness claims for beta testing and GA launch

**Repository:** argus-action (self-scan)
- **Files:** 131 Python files
- **Lines:** ~40,550 lines of code
- **Type:** Medium-sized backend security tool

---

## 📊 Claims to Validate

From CHANGELOG.md v4.1.0:

| Claim | Target | How to Validate |
|-------|--------|-----------------|
| **Per-scan cost** | $0.57-0.75 | Track API token usage |
| **Scan time** | <5 min | Measure end-to-end time |
| **Test pass rate** | 89.4% | ✅ Already validated |
| **Scanner count** | 5 active | Count scanner outputs |
| **False positive reduction** | 60-70% | Compare pre/post AI triage |

---

## 🚀 Benchmark Script

### Quick Benchmark (5 minutes)
```bash
#!/bin/bash
# Run single scan with timing and cost tracking

echo "=== Argus v4.1.0 Benchmark Scan ==="
echo "Repository: $(pwd)"
echo "Start time: $(date)"
START_TIME=$(date +%s)

# Set API key (required)
export ANTHROPIC_API_KEY="your-key-here"

# Run scan with all features
python scripts/run_ai_audit.py \
  --project-type backend-api \
  --ai-provider anthropic \
  --output-file benchmark_results.json \
  --debug 2>&1 | tee benchmark_scan.log

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

echo "End time: $(date)"
echo "Duration: ${DURATION}s ($(echo "scale=2; $DURATION/60" | bc) minutes)"

# Parse results
echo ""
echo "=== Scan Results ==="
cat benchmark_results.json | jq '{
  total_findings: .total_findings,
  critical: .severity_breakdown.critical,
  high: .severity_breakdown.high,
  scanners_used: (.scanners_run | length),
  ai_triaged: .ai_triage_stats.findings_triaged
}'

# Extract cost (if available in logs)
echo ""
echo "=== Cost Analysis ==="
grep -i "cost\|tokens\|api" benchmark_scan.log | tail -10
```

---

## 📈 Detailed Benchmark Plan

### Test 1: Base Scan (No AI)
**Purpose:** Measure scanner performance only

```bash
python scripts/run_ai_audit.py \
  --project-type backend-api \
  --output-file results_no_ai.json \
  --ai-provider none  # Skip AI triage
```

**Collect:**
- Scan time
- Raw findings count
- Scanner breakdown

### Test 2: Full Scan (With AI)
**Purpose:** Measure AI triage effectiveness

```bash
export ANTHROPIC_API_KEY="your-key-here"

python scripts/run_ai_audit.py \
  --project-type backend-api \
  --ai-provider anthropic \
  --output-file results_with_ai.json
```

**Collect:**
- Total scan time
- API token usage
- Findings before triage
- Findings after triage
- False positive reduction %

### Test 3: Cached Re-scan
**Purpose:** Measure cache effectiveness

```bash
# Run same scan again (should use cache)
python scripts/run_ai_audit.py \
  --project-type backend-api \
  --ai-provider anthropic \
  --output-file results_cached.json
```

**Expected:**
- **10-100x faster** (should be <30s)
- **Near-zero cost** (cache hits)

### Test 4: Individual Scanners
**Purpose:** Measure scanner breakdown

```bash
# TruffleHog only
time python scripts/trufflehog_scanner.py scan . --output trufflehog.json

# Gitleaks only
time gitleaks detect --source . --report-path gitleaks.json

# Semgrep only
time semgrep --config=auto --json --output semgrep.sarif .

# Trivy only
time trivy fs --format json --output trivy.json .
```

**Collect:**
- Time per scanner
- Findings per scanner
- Overlap analysis

---

## 🎯 Expected Results

Based on v4.1.0 claims:

### Performance
| Metric | Target | Pass Criteria |
|--------|--------|---------------|
| **Total scan time** | <5 min | ✅ if <300s |
| **Scanner time** | ~40s | ✅ if <60s |
| **AI triage time** | ~2-3 min | ✅ if <240s |
| **Cached re-scan** | <30s | ✅ if 10-100x faster |

### Cost
| Component | Estimated Cost |
|-----------|----------------|
| **Scanners** | $0 (free) |
| **AI Triage** | $0.50-0.70 |
| **Total** | **$0.50-0.70** ✅ |

**Validation:** Track actual tokens used
```bash
# Example calculation
Total tokens: 150,000
Claude Sonnet rate: $3/million input, $15/million output
Cost = (100k input * $3/1M) + (50k output * $15/1M) = $0.30 + $0.75 = $1.05
```

### Quality
| Metric | Target | How to Measure |
|--------|--------|----------------|
| **Findings detected** | 50-200 | Count in results.json |
| **False positives** | 60-70% reduced | Compare pre/post AI |
| **Critical findings** | 5-15 | High-value bugs |
| **Scanner coverage** | 5 scanners | TruffleHog, Gitleaks, Semgrep, Trivy, Supply Chain |

---

## 📝 Benchmark Report Template

```markdown
# Argus v4.1.0 Benchmark Results

**Repository:** argus-action
**Date:** YYYY-MM-DD
**Scanner Version:** v4.1.0

## Performance

| Metric | Result | Target | Status |
|--------|--------|--------|--------|
| Total scan time | Xs | <300s | ✅/❌ |
| Scanner execution | Xs | <60s | ✅/❌ |
| AI triage time | Xs | <240s | ✅/❌ |
| Cached re-scan | Xs | <30s | ✅/❌ |

## Cost

| Component | Tokens | Cost | Notes |
|-----------|--------|------|-------|
| Input tokens | X | $X.XX | |
| Output tokens | X | $X.XX | |
| **Total** | **X** | **$X.XX** | Target: $0.50-0.70 |

## Quality

| Metric | Count | Notes |
|--------|-------|-------|
| Total findings | X | Before AI triage |
| After AI triage | X | False positives removed |
| Critical | X | High priority |
| High | X | |
| Medium | X | |
| Low | X | |
| **FP Reduction** | **X%** | Target: 60-70% |

## Scanner Breakdown

| Scanner | Time | Findings | Notes |
|---------|------|----------|-------|
| TruffleHog | Xs | X | Verified secrets |
| Gitleaks | Xs | X | Pattern-based |
| Semgrep | Xs | X | SAST rules |
| Trivy | Xs | X | CVE scanning |
| Supply Chain | Xs | X | Dependency analysis |

## Findings Analysis

### Top 5 Critical Findings
1. [Finding description]
2. ...

### False Positive Examples
1. [FP that was correctly suppressed]
2. ...

## Conclusions

- **Performance:** ✅/❌ Meets <5 min target
- **Cost:** ✅/❌ Within $0.50-0.70 range
- **Quality:** ✅/❌ 60-70% FP reduction

### Recommendations
- [Any adjustments needed]
- [Configuration optimizations]
```

---

## 🔧 Troubleshooting

### High Cost
**If cost > $1.00:**
- Check token usage in logs
- Verify caching is working
- Consider Ollama for free local LLM

### Slow Performance
**If scan time > 5 min:**
- Check network latency to scanners
- Verify parallel execution is working
- Review scanner timeout settings

### Low Detection Rate
**If findings < 50:**
- Repository may be very secure (good!)
- Check scanner configurations
- Verify all 5 scanners are running

---

## 📊 Real-World Benchmark Data

To be filled in after running benchmarks:

### Scan 1: argus-action (this repo)
```
Date: ____
Time: ____
Cost: $____
Findings: ____
```

### Scan 2: Different repo
```
Date: ____
Time: ____
Cost: $____
Findings: ____
```

---

## ✅ Quick Validation Checklist

Before beta testing, confirm:

- [ ] Scan completes in <5 minutes
- [ ] Cost is <$1.00 per scan
- [ ] At least 3 scanners produce findings
- [ ] AI triage reduces noise by >50%
- [ ] Cached re-scan is 10x+ faster
- [ ] No crashes or errors
- [ ] Results are actionable

---

## 🚀 Next Steps

After benchmarking:

1. **Update docs** with real numbers
2. **Share results** with beta customers
3. **Adjust pricing** if needed
4. **Optimize performance** based on data
5. **Create case study** from findings

---

**Created:** 2026-01-16
**Version:** v4.1.0
**Status:** Ready for execution (requires API key)
