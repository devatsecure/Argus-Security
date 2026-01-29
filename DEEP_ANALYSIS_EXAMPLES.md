# Deep Analysis Engine - Command Examples

> Quick reference for Phase 2.7 progressive rollout

## Week 1: Semantic Only (Getting Started)

### Example 1: Small Repo Test
```bash
# Test on a small repo (< 10 files)
python scripts/run_ai_audit.py \
  --deep-analysis-mode=semantic-only \
  --max-files-deep-analysis=10 \
  --deep-analysis-cost-ceiling=1.0

# Or using environment variables
export DEEP_ANALYSIS_MODE=semantic-only
export DEEP_ANALYSIS_MAX_FILES=10
export DEEP_ANALYSIS_COST_CEILING=1.0
python scripts/run_ai_audit.py
```

**Expected Output:**
```
🔬 PHASE 2.7: DEEP ANALYSIS ENGINE
================================================================================
   Mode: semantic-only
   Enabled phases: ['semantic']
🔍 Running semantic analysis...
   ✓ 8 files, 1 findings, 16.2s
✅ Deep Analysis complete: 1 findings, $0.24 cost
```

### Example 2: Dry Run First
```bash
# ALWAYS dry-run before committing to production
python scripts/run_ai_audit.py \
  --deep-analysis-mode=semantic-only \
  --deep-analysis-dry-run

# Review estimate, then run for real
python scripts/run_ai_audit.py \
  --deep-analysis-mode=semantic-only \
  --max-files-deep-analysis=15
```

---

## Week 2: Conservative Mode (Scaling Up)

### Example 3: Medium Repo Analysis
```bash
# Scale to 30 files, add proactive scanner
python scripts/run_ai_audit.py \
  --project-type backend-api \
  --deep-analysis-mode=conservative \
  --max-files-deep-analysis=30 \
  --deep-analysis-cost-ceiling=3.0
```

**Expected Output:**
```
🔬 PHASE 2.7: DEEP ANALYSIS ENGINE
================================================================================
   Mode: conservative
   Enabled phases: ['semantic', 'proactive']
🔍 Running semantic analysis...
   ✓ 30 files, 2 findings, 62.3s
🔍 Running proactive analysis...
   ✓ 30 files, 3 findings, 95.7s
✅ Deep Analysis complete: 5 findings, $2.55 cost
```

### Example 4: CI/CD Integration
```bash
# .github/workflows/security.yml
- name: Argus Security Scan
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
    DEEP_ANALYSIS_MODE: conservative
    DEEP_ANALYSIS_MAX_FILES: 25
    DEEP_ANALYSIS_COST_CEILING: 2.0
  run: |
    python scripts/run_ai_audit.py --project-type backend-api
```

---

## Week 3: Full Mode (Pre-Release Audits)

### Example 5: Comprehensive Security Audit
```bash
# Full analysis with all modules
python scripts/run_ai_audit.py \
  --project-type backend-api \
  --deep-analysis-mode=full \
  --max-files-deep-analysis=50 \
  --deep-analysis-cost-ceiling=5.0
```

**Expected Output:**
```
🔬 PHASE 2.7: DEEP ANALYSIS ENGINE
================================================================================
   Mode: full
   Enabled phases: ['semantic', 'proactive', 'taint', 'zero_day']
🔍 Running semantic analysis...
   ✓ 50 files, 3 findings, 102.5s
🔍 Running proactive analysis...
   ✓ 50 files, 5 findings, 158.3s
🔍 Running taint analysis...
   ✓ 50 files, 2 findings, 264.8s
🔍 Running zero_day analysis...
   ✓ 50 files, 1 findings, 412.1s
✅ Deep Analysis complete: 11 findings, $4.87 cost
📝 Deep analysis results exported to argus_deep_analysis_results.json
```

### Example 6: Critical Repos Only
```bash
# Target specific high-value repos
for repo in auth-service payment-gateway user-api; do
  echo "🔐 Auditing $repo..."
  cd $repo
  python ../scripts/run_ai_audit.py \
    --deep-analysis-mode=full \
    --deep-analysis-cost-ceiling=10.0
  cd ..
done
```

---

## Week 4: Production Rollout

### Example 7: Tiered Deployment
```bash
# Tier 1: Critical repos (full analysis)
if [ "$REPO_TIER" = "critical" ]; then
  export DEEP_ANALYSIS_MODE=full
  export DEEP_ANALYSIS_MAX_FILES=100
  export DEEP_ANALYSIS_COST_CEILING=10.0

# Tier 2: Standard repos (conservative)
elif [ "$REPO_TIER" = "standard" ]; then
  export DEEP_ANALYSIS_MODE=conservative
  export DEEP_ANALYSIS_MAX_FILES=50
  export DEEP_ANALYSIS_COST_CEILING=3.0

# Tier 3: Low priority (semantic only)
else
  export DEEP_ANALYSIS_MODE=semantic-only
  export DEEP_ANALYSIS_MAX_FILES=25
  export DEEP_ANALYSIS_COST_CEILING=1.0
fi

python scripts/run_ai_audit.py
```

### Example 8: Scheduled Nightly Scans
```bash
# cron: 0 2 * * * /path/to/nightly-scan.sh
#!/bin/bash
set -e

export DEEP_ANALYSIS_MODE=conservative
export DEEP_ANALYSIS_MAX_FILES=100
export DEEP_ANALYSIS_COST_CEILING=5.0

cd /repos/monorepo
python scripts/run_ai_audit.py --project-type monorepo

# Email results
if [ $? -eq 0 ]; then
  mail -s "✅ Nightly Security Scan Complete" team@company.com < argus_deep_analysis_results.json
else
  mail -s "❌ Nightly Security Scan Failed" team@company.com < argus_audit.log
fi
```

---

## Standalone Deep Analysis Engine

### Example 9: Direct CLI Usage
```bash
# Use argus_deep_analysis.py directly (without full pipeline)
python scripts/argus_deep_analysis.py \
  /path/to/repo \
  --mode=conservative \
  --max-files=30 \
  --cost-ceiling=3.0 \
  --output=results.json

# With benchmark reporting
python scripts/argus_deep_analysis.py \
  /path/to/repo \
  --mode=full \
  --benchmark
```

**Benchmark Output:**
```
=====================================================================================
=== Deep Analysis Benchmark Report ===
=====================================================================================
Phase                     Time       Tokens (In/Out)      Cost       Findings
-------------------------------------------------------------------------------------
Semantic Code Twin        62.3s      45K / 12K            $0.315     3
Proactive Scanner         95.7s      68K / 22K            $0.534     5
Taint Analysis            264.8s     112K / 38K           $0.906     2
Zero Day Hunter           412.1s     156K / 52K           $1.248     1
-------------------------------------------------------------------------------------
TOTAL                     834.9s     381K / 124K          $3.003     11
=====================================================================================

📊 Additional Statistics:
   Files analyzed/sec: 0.06
   Files analyzed: 50
   Total tokens: 505,000
   Avg cost per finding: $0.2730

📈 Phase Breakdown:
   semantic: 3 findings
   proactive: 5 findings
   taint: 2 findings
   zero_day: 1 findings
```

---

## Advanced Tuning

### Example 10: Cost-Optimized Scan
```bash
# Minimize cost while maximizing value
python scripts/run_ai_audit.py \
  --deep-analysis-mode=conservative \
  --max-files-deep-analysis=20 \
  --deep-analysis-cost-ceiling=1.5

# Focus on high-risk files only (custom filter)
export DEEP_ANALYSIS_FILE_PATTERN="**/auth/**/*.py,**/api/**/*.py"
python scripts/run_ai_audit.py --deep-analysis-mode=full
```

### Example 11: Emergency Rollback
```bash
# Instant rollback - disable deep analysis
export DEEP_ANALYSIS_MODE=off
python scripts/run_ai_audit.py

# Or via CLI
python scripts/run_ai_audit.py --deep-analysis-mode=off
```

### Example 12: A/B Testing
```bash
# Run baseline (without deep analysis)
python scripts/run_ai_audit.py \
  --deep-analysis-mode=off \
  > baseline_findings.json

# Run with deep analysis
python scripts/run_ai_audit.py \
  --deep-analysis-mode=conservative \
  > deep_findings.json

# Compare results
diff <(jq '.total_findings' baseline_findings.json) \
     <(jq '.total_findings' deep_findings.json)
```

---

## Monitoring & Observability

### Example 13: Cost Tracking
```bash
# Track daily costs
jq '.total_cost' argus_deep_analysis_results.json >> daily_costs.txt

# Weekly summary
awk '{sum+=$1} END {print "Weekly total: $" sum}' daily_costs.txt
```

### Example 14: False Positive Analysis
```bash
# Extract findings with confidence < 0.75
jq '.results[].findings[] | select(.confidence < 0.75)' \
  argus_deep_analysis_results.json

# Mark as false positive
./scripts/argus feedback record deep_analysis_42 --mark fp
```

---

## Integration Examples

### Example 15: GitLab CI
```yaml
# .gitlab-ci.yml
argus_deep_analysis:
  stage: security
  script:
    - export DEEP_ANALYSIS_MODE=conservative
    - export DEEP_ANALYSIS_MAX_FILES=30
    - python scripts/run_ai_audit.py
  artifacts:
    paths:
      - argus_deep_analysis_results.json
    when: always
  only:
    - main
    - merge_requests
```

### Example 16: Jenkins Pipeline
```groovy
// Jenkinsfile
pipeline {
  stages {
    stage('Deep Analysis') {
      when {
        branch 'main'
      }
      environment {
        DEEP_ANALYSIS_MODE = 'full'
        DEEP_ANALYSIS_COST_CEILING = '10.0'
      }
      steps {
        sh 'python scripts/run_ai_audit.py --project-type backend-api'
      }
      post {
        always {
          archiveArtifacts artifacts: 'argus_deep_analysis_results.json'
        }
      }
    }
  }
}
```

---

## Troubleshooting Commands

### Example 17: Debug Mode
```bash
# Enable verbose logging
export LOG_LEVEL=DEBUG
python scripts/run_ai_audit.py \
  --deep-analysis-mode=conservative \
  2>&1 | tee deep_analysis_debug.log
```

### Example 18: Cost Ceiling Hit
```bash
# If you see: ⚠️ Estimated cost $15.23 exceeds ceiling $10.00

# Option 1: Reduce file count
python scripts/run_ai_audit.py \
  --deep-analysis-mode=full \
  --max-files-deep-analysis=30  # Reduced from 50

# Option 2: Downgrade mode
python scripts/run_ai_audit.py \
  --deep-analysis-mode=conservative  # Instead of full

# Option 3: Increase ceiling (if justified)
python scripts/run_ai_audit.py \
  --deep-analysis-mode=full \
  --deep-analysis-cost-ceiling=20.0
```

---

## Summary: Decision Tree

```
Choose your mode based on:

┌─────────────────────────────────────────────────────────────┐
│ Budget < $1/scan?        → semantic-only                    │
│ Daily monitoring?        → conservative                     │
│ Pre-release audit?       → full                             │
│ Critical system?         → full                             │
│ Large codebase (>100)?   → semantic-only + reduce max-files │
│ Testing deep analysis?   → --dry-run first!                 │
└─────────────────────────────────────────────────────────────┘
```

For more details, see: `/Users/waseem.ahmed/Repos/Argus-Security/docs/deep-analysis-migration.md`

---

## Safety Controls Reference

### Quick Reference Table

| Scenario | Max Files | Timeout | Cost Ceiling | Mode |
|----------|-----------|---------|--------------|------|
| PR Review | 20 | 120s | $0.50 | semantic-only |
| CI/CD Pipeline | 25 | 180s | $1.00 | conservative |
| Local Dev | 50 | 300s | $5.00 | conservative |
| Nightly Scan | 100 | 900s | $10.00 | conservative |
| Full Audit | 200 | 1800s | $25.00 | full |

### Command Templates

**PR Review:**
```bash
python scripts/run_ai_audit.py . --deep-analysis-mode=semantic-only --max-files-deep-analysis=20 --deep-analysis-timeout=120 --deep-analysis-cost-ceiling=0.50
```

**CI/CD:**
```bash
python scripts/run_ai_audit.py . --deep-analysis-mode=conservative --max-files-deep-analysis=25 --deep-analysis-timeout=180 --deep-analysis-cost-ceiling=1.0
```

**Local Dev:**
```bash
python scripts/run_ai_audit.py . --enable-deep-analysis
```

**Nightly:**
```bash
python scripts/run_ai_audit.py . --deep-analysis-mode=conservative --max-files-deep-analysis=100 --deep-analysis-timeout=900 --deep-analysis-cost-ceiling=10.0
```

**Full Audit:**
```bash
python scripts/run_ai_audit.py . --deep-analysis-mode=full --max-files-deep-analysis=200 --deep-analysis-timeout=1800 --deep-analysis-cost-ceiling=25.0
```

