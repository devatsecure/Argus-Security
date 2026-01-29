# Deep Analysis Engine Migration Guide

> **Phase 2.7: Progressive Rollout Strategy for Advanced Security Analysis**

## Table of Contents

- [Overview](#overview)
- [Capabilities](#capabilities)
- [Progressive Rollout Strategy](#progressive-rollout-strategy)
- [Cost & Performance Expectations](#cost--performance-expectations)
- [Feature Flags Reference](#feature-flags-reference)
- [Usage Examples](#usage-examples)
- [Interpreting Results](#interpreting-results)
- [Troubleshooting](#troubleshooting)
- [Rollback Instructions](#rollback-instructions)

---

## Overview

The **Deep Analysis Engine** (Phase 2.7) is an advanced security analysis module that uses cutting-edge AI techniques to discover vulnerabilities that traditional scanners miss. It runs between Phase 2 (Planning) and Phase 3 (Implementation) of the Argus 6-phase pipeline.

### Key Features

- **Progressive Rollout**: Granular feature flags allow safe, controlled adoption
- **Cost Controls**: Built-in cost ceilings and dry-run mode prevent unexpected LLM charges
- **Multi-Module Architecture**: Enable only the modules you need
- **Backwards Compatible**: Defaults to `off` mode - existing workflows unchanged

### Why Deep Analysis?

Traditional SAST tools rely on pattern matching and pre-defined rules. Deep Analysis Engine uses:
- **Semantic understanding** of code logic (not just syntax)
- **Proactive hypothesis generation** based on codebase patterns
- **Taint flow tracking** across complex call chains
- **Novel pattern detection** for zero-day vulnerabilities

**Expected Results**: +10-15% more findings, discovery of business logic vulnerabilities that regex-based tools miss.

---

## Capabilities

### Module 1: Semantic Code Twin Analysis
**Mode**: `semantic-only`

**What it does:**
- Detects duplicated logic across files using embeddings
- Identifies similar vulnerable patterns (e.g., 3 auth implementations with subtle differences)
- Finds inconsistent security controls

**Example Finding:**
```json
{
  "type": "semantic_clone",
  "severity": "medium",
  "title": "Duplicated authentication logic detected",
  "description": "Similar auth validation code found in 3 files - consolidate to prevent inconsistencies",
  "files": ["auth/login.py", "auth/register.py", "api/verify.py"],
  "confidence": 0.92
}
```

**Cost**: ~$0.03 per file
**Speed**: ~2 seconds per file
**Best For**: Large codebases with copy-paste patterns

---

### Module 2: Proactive Scanner
**Mode**: `conservative` (includes Semantic + Proactive)

**What it does:**
- Generates hypotheses about potential vulnerabilities based on codebase context
- Goes beyond known CVE patterns to find custom vulnerability classes
- Analyzes framework-specific anti-patterns

**Example Finding:**
```json
{
  "type": "proactive_finding",
  "severity": "high",
  "title": "Potential SSRF in URL handling",
  "description": "User-controlled URL passed to requests library without validation",
  "file": "api/webhook.py",
  "line": 45,
  "confidence": 0.78
}
```

**Cost**: ~$0.05 per file
**Speed**: ~3 seconds per file
**Best For**: Custom-built applications, business logic vulnerabilities

---

### Module 3: Taint Analysis
**Mode**: `full` (includes all modules)

**What it does:**
- Tracks data flow from sources (user input) to sinks (dangerous operations)
- Multi-hop taint propagation across function boundaries
- Detects injection vulnerabilities with complex paths

**Example Finding:**
```json
{
  "type": "taint_flow",
  "severity": "critical",
  "title": "SQL injection via tainted user input",
  "description": "User input flows to SQL query without sanitization",
  "source": "request.args['user_id']",
  "sink": "db.execute(query)",
  "taint_path": ["request.args", "validate_input", "build_query", "db.execute"],
  "confidence": 0.95
}
```

**Cost**: ~$0.08 per file
**Speed**: ~5 seconds per file
**Best For**: Web applications, APIs with complex data flows

---

### Module 4: Zero-Day Hunter
**Mode**: `full`

**What it does:**
- Uses advanced LLM reasoning to identify novel vulnerability patterns
- Detects race conditions, TOCTOU bugs, logic flaws
- Flags unusual code patterns that may indicate security issues

**Example Finding:**
```json
{
  "type": "zero_day_candidate",
  "severity": "critical",
  "title": "Novel race condition in cache invalidation",
  "description": "Time-of-check-time-of-use vulnerability in distributed cache",
  "file": "cache/manager.py",
  "line": 123,
  "confidence": 0.72,
  "novelty_score": 0.88
}
```

**Cost**: ~$0.10 per file
**Speed**: ~8 seconds per file
**Best For**: Critical systems, pre-release security hardening

---

## Progressive Rollout Strategy

### Week 1: Semantic Only (Low Risk)
**Goal**: Validate infrastructure, establish baseline

```bash
# Start with smallest repos (<10 files)
export DEEP_ANALYSIS_MODE=semantic-only
export DEEP_ANALYSIS_MAX_FILES=10
export DEEP_ANALYSIS_COST_CEILING=1.0

python scripts/run_ai_audit.py --deep-analysis-mode=semantic-only
```

**Expected Metrics:**
- **Files analyzed**: 5-10
- **Time**: 10-20 seconds
- **Cost**: $0.15-$0.30
- **Findings**: 0-2 semantic clones

**Success Criteria:**
- [ ] No runtime errors
- [ ] Cost under $1.00
- [ ] Results exported to `argus_deep_analysis_results.json`
- [ ] At least one true positive finding

---

### Week 2: Conservative Mode (Medium Risk)
**Goal**: Scale to production-sized repos, validate proactive scanner

```bash
# Scale to medium repos (20-50 files)
export DEEP_ANALYSIS_MODE=conservative
export DEEP_ANALYSIS_MAX_FILES=30
export DEEP_ANALYSIS_COST_CEILING=3.0

python scripts/run_ai_audit.py \
  --deep-analysis-mode=conservative \
  --max-files-deep-analysis=30
```

**Expected Metrics:**
- **Files analyzed**: 20-30
- **Time**: 90-150 seconds (~2.5 min)
- **Cost**: $1.50-$2.40
- **Findings**: 2-5 total (semantic + proactive)

**Success Criteria:**
- [ ] Cost stays under ceiling
- [ ] Proactive scanner finds at least 1 novel issue
- [ ] False positive rate < 30%
- [ ] No performance degradation in CI/CD

---

### Week 3: Full Mode with Safety Net (High Risk)
**Goal**: Enable all modules with conservative cost ceiling

```bash
# Run on selected critical repos only
export DEEP_ANALYSIS_MODE=full
export DEEP_ANALYSIS_MAX_FILES=50
export DEEP_ANALYSIS_COST_CEILING=5.0

python scripts/run_ai_audit.py \
  --deep-analysis-mode=full \
  --deep-analysis-cost-ceiling=5.0 \
  --max-files-deep-analysis=50
```

**Expected Metrics:**
- **Files analyzed**: 40-50
- **Time**: 400-600 seconds (~7-10 min)
- **Cost**: $4.00-$5.00
- **Findings**: 5-15 total (all modules)

**Success Criteria:**
- [ ] Taint analysis finds at least 1 flow vulnerability
- [ ] Zero-day hunter identifies at least 1 novel pattern
- [ ] Total cost < $5.00
- [ ] At least 60% of findings are actionable

---

### Week 4: Production Rollout
**Goal**: Enable on all repos with appropriate tier-based settings

```bash
# Tier 1: Critical repos (full analysis)
python scripts/run_ai_audit.py \
  --deep-analysis-mode=full \
  --max-files-deep-analysis=100 \
  --deep-analysis-cost-ceiling=10.0

# Tier 2: Standard repos (conservative)
python scripts/run_ai_audit.py \
  --deep-analysis-mode=conservative \
  --max-files-deep-analysis=50

# Tier 3: Low priority (semantic only or off)
python scripts/run_ai_audit.py \
  --deep-analysis-mode=semantic-only \
  --max-files-deep-analysis=25
```

**Ongoing Monitoring:**
- Track cost per repo using `argus_deep_analysis_results.json`
- Monitor false positive rate via feedback system
- Adjust cost ceilings based on value delivered

---

## Cost & Performance Expectations

### Cost Breakdown by Mode

| Mode | Modules Enabled | Cost/File | Total (50 files) | Time (50 files) |
|------|-----------------|-----------|------------------|-----------------|
| `off` | None | $0.00 | $0.00 | 0s |
| `semantic-only` | Semantic Twin | $0.03 | $1.50 | 100s |
| `conservative` | Semantic + Proactive | $0.08 | $4.00 | 250s |
| `full` | All 4 modules | $0.26 | $13.00 | 900s |

**Note**: Costs based on Claude Sonnet 3.5 pricing ($3/MTok input, $15/MTok output). Actual costs may vary based on file complexity.

### When to Use Each Mode

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Mode Selection Guide                        │
├─────────────────┬───────────────────────────────────────────────────┤
│ off             │ Default, backwards compatibility                  │
│ semantic-only   │ Large codebases, refactoring projects            │
│ conservative    │ Pre-merge PR checks, continuous monitoring        │
│ full            │ Pre-release audits, critical systems, pen testing │
└─────────────────┴───────────────────────────────────────────────────┘
```

### Dry-Run Cost Estimation

**ALWAYS run dry-run before enabling on new repos:**

```bash
python scripts/run_ai_audit.py \
  --deep-analysis-mode=full \
  --deep-analysis-dry-run
```

**Output:**
```
🧮 Estimating deep analysis cost...
📊 Estimate:
   Files: 47/52
   Time: ~658s
   Cost: ~$12.20
   Breakdown: {'semantic': 1.41, 'proactive': 2.35, 'taint': 3.76, 'zero_day': 4.70}
```

**Decision Rules:**
- If cost > $5.00: Reduce `--max-files-deep-analysis`
- If time > 600s: Consider running async or overnight
- If cost > $20.00: Re-evaluate mode (consider `conservative`)

---

## Feature Flags Reference

### Command-Line Flags

```bash
--deep-analysis-mode=<mode>
    Choices: off, semantic-only, conservative, full
    Default: off (or DEEP_ANALYSIS_MODE env var)

--max-files-deep-analysis=<int>
    Max files to analyze (default: 100)
    Overrides: DEEP_ANALYSIS_MAX_FILES

--deep-analysis-cost-ceiling=<float>
    Cost ceiling in USD (default: 10.0)
    Overrides: DEEP_ANALYSIS_COST_CEILING

--deep-analysis-dry-run
    Estimate cost without running LLM calls
    No cost incurred, fast execution
```

### Environment Variables

```bash
# Primary configuration
export DEEP_ANALYSIS_MODE=conservative
export DEEP_ANALYSIS_MAX_FILES=50
export DEEP_ANALYSIS_COST_CEILING=5.0

# Advanced tuning (optional)
export DEEP_ANALYSIS_MIN_SIMILARITY=0.85  # Semantic twin threshold
export DEEP_ANALYSIS_TAINT_MAX_DEPTH=5    # Taint propagation depth
export DEEP_ANALYSIS_ZERO_DAY_CONFIDENCE=0.7  # Zero-day threshold
```

**Precedence**: CLI flags > Environment variables > Defaults

---

## Usage Examples

### Example 1: Quick Semantic Check (PR Gate)

```bash
# Fast, cheap, catches obvious duplication
python scripts/run_ai_audit.py \
  --project-type backend-api \
  --deep-analysis-mode=semantic-only \
  --max-files-deep-analysis=20

# Expected: 20-40 seconds, $0.30-$0.60
```

**Use Case**: PR checks, daily continuous monitoring

---

### Example 2: Comprehensive Pre-Release Audit

```bash
# Full analysis with safety net
python scripts/run_ai_audit.py \
  --project-type backend-api \
  --deep-analysis-mode=full \
  --deep-analysis-cost-ceiling=15.0

# Expected: 10-20 minutes, $10-$15 for 100-file repo
```

**Use Case**: Release candidate validation, security hardening

---

### Example 3: Cost-Conscious Continuous Monitoring

```bash
# Conservative mode with strict limits
export DEEP_ANALYSIS_MODE=conservative
export DEEP_ANALYSIS_MAX_FILES=25
export DEEP_ANALYSIS_COST_CEILING=2.0

python scripts/run_ai_audit.py --project-type backend-api

# Expected: 2-3 minutes, $1.50-$2.00
```

**Use Case**: Daily scans, budget-constrained environments

---

### Example 4: Dry-Run Before Production

```bash
# Estimate first, decide later
python scripts/run_ai_audit.py \
  --deep-analysis-mode=full \
  --deep-analysis-dry-run

# Review estimate, then run for real:
python scripts/run_ai_audit.py \
  --deep-analysis-mode=full \
  --max-files-deep-analysis=30  # Adjust based on estimate
```

**Use Case**: New repositories, unknown codebases

---

## Interpreting Results

### Results File Location

```
<repo_path>/argus_deep_analysis_results.json
```

### Results Schema

```json
{
  "mode": "conservative",
  "enabled_phases": ["semantic", "proactive"],
  "total_cost": 3.45,
  "total_findings": 7,
  "results": [
    {
      "phase": "semantic",
      "findings": [...],
      "files_analyzed": 30,
      "execution_time": 62.3,
      "estimated_cost": 0.90
    },
    {
      "phase": "proactive",
      "findings": [...],
      "files_analyzed": 30,
      "execution_time": 95.7,
      "estimated_cost": 2.55
    }
  ]
}
```

### Finding Severity Levels

| Severity | Action | Examples |
|----------|--------|----------|
| **critical** | Block merge, immediate fix | SQL injection, RCE, auth bypass |
| **high** | Fix before release | SSRF, path traversal, sensitive data leak |
| **medium** | Fix in sprint | Weak crypto, missing rate limits |
| **low** | Backlog | Code duplication, minor inefficiencies |

### Confidence Scores

- **0.90-1.00**: Very high confidence, likely true positive
- **0.75-0.89**: High confidence, review recommended
- **0.60-0.74**: Medium confidence, may be false positive
- **< 0.60**: Low confidence, likely noise (not reported by default)

### Integration with Main Findings

Deep analysis findings are merged into the main `findings` dictionary:

```python
findings = {
  "secrets": [...],  # Phase 1
  "vulnerabilities": [...],  # Phase 1
  "deep_analysis_semantic": [...],  # Phase 2.7
  "deep_analysis_proactive": [...],  # Phase 2.7
  "deep_analysis_taint": [...],  # Phase 2.7
  "deep_analysis_zero_day": [...]  # Phase 2.7
}
```

---

## Troubleshooting

### Issue 1: Cost Ceiling Exceeded

**Symptom:**
```
⚠️  Estimated cost $15.23 exceeds ceiling $10.00
   Consider reducing --max-files-deep-analysis or increasing --deep-analysis-cost-ceiling
```

**Solutions:**
1. **Reduce file count**: `--max-files-deep-analysis=50` → `--max-files-deep-analysis=30`
2. **Lower mode**: `--deep-analysis-mode=full` → `--deep-analysis-mode=conservative`
3. **Increase ceiling**: `--deep-analysis-cost-ceiling=15.0` (if budget allows)
4. **Target specific dirs**: Run on `src/` only, skip `tests/`

---

### Issue 2: Deep Analysis Engine Not Available

**Symptom:**
```
⏭️  Phase 2.7: Deep Analysis Engine not available
```

**Cause**: `argus_deep_analysis.py` not in path or import error

**Solution:**
```bash
# Verify file exists
ls -l scripts/argus_deep_analysis.py

# Test import
python3 -c "from scripts.argus_deep_analysis import DeepAnalysisEngine; print('OK')"

# If missing, reinstall
git pull origin main
```

---

### Issue 3: Slow Execution

**Symptom**: Analysis takes >15 minutes for 50 files

**Causes & Solutions:**

| Cause | Solution |
|-------|----------|
| Rate limiting | Add retry delays, reduce concurrency |
| Large files | Filter out generated code (minified JS, etc.) |
| Network latency | Use regional API endpoints |
| Full mode on large repo | Switch to `conservative` or reduce `--max-files` |

**Monitoring:**
```bash
# Watch progress in real-time
tail -f argus_audit.log

# Check per-phase timing
jq '.results[] | {phase, execution_time}' argus_deep_analysis_results.json
```

---

### Issue 4: High False Positive Rate

**Symptom**: >40% of findings are false positives

**Triage Process:**

1. **Check confidence scores**:
   ```bash
   jq '.results[].findings[] | select(.confidence < 0.7)' \
     argus_deep_analysis_results.json | wc -l
   ```

2. **Adjust thresholds**:
   ```bash
   export DEEP_ANALYSIS_ZERO_DAY_CONFIDENCE=0.8  # Raise bar
   ```

3. **Provide feedback**:
   ```bash
   ./scripts/argus feedback record <finding_id> --mark fp
   ```

4. **Filter by severity**:
   ```bash
   # Focus on critical/high only
   jq '.results[].findings[] | select(.severity == "critical" or .severity == "high")'
   ```

---

### Issue 5: No Findings Generated

**Symptom**: `total_findings: 0` in results

**Diagnostic Steps:**

1. **Check if mode is off**:
   ```bash
   # Should show mode other than "off"
   jq '.mode' argus_deep_analysis_results.json
   ```

2. **Verify files were analyzed**:
   ```bash
   jq '.results[].files_analyzed' argus_deep_analysis_results.json
   # Should be > 0
   ```

3. **Check for errors**:
   ```bash
   grep -i "error\|exception" argus_audit.log
   ```

4. **Review file filters**:
   - Ensure target files have supported extensions (`.py`, `.js`, `.java`, etc.)
   - Check that files aren't filtered out (e.g., in `node_modules/`, `venv/`)

---

## Rollback Instructions

### Immediate Rollback (0 downtime)

```bash
# Option 1: Disable via environment variable
export DEEP_ANALYSIS_MODE=off
python scripts/run_ai_audit.py

# Option 2: Disable via CLI flag
python scripts/run_ai_audit.py --deep-analysis-mode=off

# Option 3: Remove from CI/CD config
# Edit .github/workflows/security.yml
# Remove or comment out deep analysis flags
```

**Effect**: Phase 2.7 skipped, all other phases continue normally. No breaking changes.

---

### Partial Rollback (Downgrade Mode)

```bash
# If full mode is problematic, downgrade to conservative
export DEEP_ANALYSIS_MODE=conservative

# If conservative is problematic, downgrade to semantic-only
export DEEP_ANALYSIS_MODE=semantic-only
```

---

### Data Cleanup (Optional)

```bash
# Remove deep analysis results files
find . -name "argus_deep_analysis_results.json" -delete

# Remove from findings exports
# Edit scripts/run_ai_audit.py, comment out lines 3672-3746
```

---

### CI/CD Pipeline Rollback

**GitHub Actions:**
```yaml
# .github/workflows/security.yml
- uses: devatsecure/Argus-Security@v1
  with:
    anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
    review-type: security
    # deep-analysis-mode: conservative  # COMMENTED OUT
    fail-on-blockers: true
```

**GitLab CI:**
```yaml
# .gitlab-ci.yml
argus_security:
  script:
    - export DEEP_ANALYSIS_MODE=off  # ADD THIS LINE
    - python scripts/run_ai_audit.py
```

---

## Best Practices

### 1. Start Small, Scale Gradually
- Week 1: 1-2 small repos, semantic-only
- Week 2: 5-10 medium repos, conservative
- Week 3: Critical repos only, full mode
- Week 4: Tiered rollout to all repos

### 2. Monitor Costs Closely
```bash
# Daily cost tracking
jq '.total_cost' argus_deep_analysis_results.json | \
  awk '{sum+=$1} END {print "Total this week: $" sum}'
```

### 3. Tune Thresholds Based on Feedback
- Collect false positive data for 2 weeks
- Adjust confidence thresholds to achieve <20% FP rate
- Document findings that required threshold tuning

### 4. Use Dry-Run Liberally
- Always dry-run before enabling full mode
- Re-dry-run after major codebase changes
- Set up alerts if estimated cost > threshold

### 5. Integrate with Feedback Loop
```bash
# After manual review, mark false positives
./scripts/argus feedback record deep_analysis_42 --mark fp

# Engine will learn from feedback in future releases
```

---

## Support & Resources

- **Documentation**: `/Users/waseem.ahmed/Repos/Argus-Security/docs/`
- **Issues**: https://github.com/devatsecure/Argus-Security/issues
- **Slack**: #argus-deep-analysis (internal)
- **Cost Calculator**: https://argus-security.dev/cost-calculator (coming soon)

---

## Changelog

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-01-29 | Initial release with 4 modules, progressive rollout |

---

**Questions?** Open an issue with tag `deep-analysis` or contact the security team.
