# Feedback Loop Quick Start Guide

## Overview

The Feedback Loop System allows Argus Security to learn from human decisions and automatically improve its false positive detection accuracy over time.

**Before Feedback Loop**: Static FP detector with fixed confidence weights
**After Feedback Loop**: Self-improving system that learns from every human review

---

## 5-Minute Quick Start

### 1. Record Your First Verdict

```bash
cd /Users/waseem.ahmed/Repos/Argus-Security

# Example: You reviewed a finding and confirmed it's a false positive
./scripts/feedback_cli.py record \
  --finding-id "semgrep-oauth2-001" \
  --automated "false_positive" \
  --human "false_positive" \
  --confidence 0.85 \
  --pattern "oauth2_localhost_pattern" \
  --category "oauth2" \
  --reasoning "Confirmed: Development OAuth2 configuration"
```

Output:
```
Recorded: Correct
```

### 2. Check Statistics

```bash
./scripts/feedback_cli.py stats
```

Output:
```
Total records: 1
Accuracy: 100.0%
False negatives: 0
False positives: 0
Patterns tracked: 1
```

### 3. Accumulate More Data

Record 10+ verdicts for meaningful tuning:

```bash
# Record more verdicts...
for i in {2..10}; do
  ./scripts/feedback_cli.py record \
    --finding-id "finding-$i" \
    --automated "false_positive" \
    --human "false_positive" \
    --confidence 0.80 \
    --pattern "oauth2_localhost_pattern" \
    --category "oauth2"
done
```

### 4. Tune Confidence Weights

```bash
# Preview adjustments (dry-run)
./scripts/feedback_cli.py tune --min-samples 10

# Apply adjustments
./scripts/feedback_cli.py tune --min-samples 10 --apply
```

Output:
```
Found 1 patterns with sufficient data:

Pattern: oauth2_localhost_pattern
  Current: 1.00
  Recommended: 1.05
  Samples: 10
  Reasoning: Accuracy: 100.0% (10 samples) | Precision: 100.0%, Recall: 100.0% | High accuracy - can increase confidence

Adjustments applied
```

### 5. Verify Changes

```bash
./scripts/feedback_cli.py accuracy --pattern oauth2_localhost_pattern
```

Output:
```
Pattern: oauth2_localhost_pattern
Samples: 10
Accuracy: 100.0%
Precision: 100.0%
Recall: 100.0%
F1 Score: 1.00
```

---

## Common Workflows

### Workflow 1: Daily Code Review

After reviewing findings from a scan:

```bash
# For each finding you reviewed:
./scripts/feedback_cli.py record \
  --finding-id "$FINDING_ID" \
  --automated "$AUTOMATED_VERDICT" \
  --human "$YOUR_VERDICT" \
  --confidence "$CONFIDENCE" \
  --pattern "$PATTERN_USED" \
  --category "$CATEGORY"
```

Example script to process multiple findings:
```bash
#!/bin/bash
# record_batch_verdicts.sh

# Read from CSV: finding_id,automated,human,confidence,pattern,category
while IFS=',' read -r finding_id automated human confidence pattern category; do
  ./scripts/feedback_cli.py record \
    --finding-id "$finding_id" \
    --automated "$automated" \
    --human "$human" \
    --confidence "$confidence" \
    --pattern "$pattern" \
    --category "$category"
done < verdicts.csv
```

### Workflow 2: Weekly Accuracy Check

Every Monday morning:

```bash
#!/bin/bash
# weekly_accuracy_check.sh

echo "=== Weekly Feedback Loop Report ==="
date

# Overall statistics
echo -e "\n--- Overall Statistics ---"
./scripts/feedback_cli.py stats

# Check key patterns
echo -e "\n--- Key Pattern Performance ---"
for pattern in oauth2_localhost_pattern file_permission_777 dev_config_pattern; do
  echo -e "\nPattern: $pattern"
  ./scripts/feedback_cli.py accuracy --pattern "$pattern" 2>/dev/null || echo "  No data yet"
done

# Suggest tuning
echo -e "\n--- Tuning Recommendations ---"
./scripts/feedback_cli.py tune --min-samples 5
```

### Workflow 3: Monthly Tuning

First Monday of each month:

```bash
#!/bin/bash
# monthly_tuning.sh

# 1. Review current state
./scripts/feedback_cli.py stats

# 2. Preview adjustments
./scripts/feedback_cli.py tune --min-samples 10

# 3. Wait for manual approval
read -p "Apply these adjustments? (yes/no) " -r
if [[ $REPLY =~ ^[Yy]es$ ]]; then
  # 4. Apply tuning
  ./scripts/feedback_cli.py tune --min-samples 10 --apply

  # 5. Commit changes
  git add .argus/feedback/confidence_adjustments.json
  git commit -m "chore: Update FP detector confidence from feedback"
  git push

  echo "Tuning applied and committed!"
else
  echo "Tuning skipped."
fi
```

---

## Integration with Existing Pipeline

### Option 1: Manual Integration (Easiest)

After running Argus scan, manually review and record:

```bash
# 1. Run normal scan
python scripts/run_ai_audit.py --project-type backend-api

# 2. Review findings in output
# 3. For each finding, record your verdict
./scripts/feedback_cli.py record \
  --finding-id "from-report" \
  --automated "false_positive" \
  --human "confirmed" \
  --confidence 0.75 \
  --pattern "pattern_name" \
  --category "oauth2"
```

### Option 2: Python Integration

Add to your existing scanning script:

```python
from feedback_loop import FeedbackLoop

# Initialize feedback loop
feedback_loop = FeedbackLoop()

# After FP detection
for finding in findings:
    # Run FP detection
    fp_result = enhanced_fp_detector.analyze(finding)

    # Apply learned confidence multiplier
    if fp_result.get("pattern_used"):
        multiplier = feedback_loop._get_current_multiplier(
            fp_result["pattern_used"]
        )
        fp_result["confidence"] *= multiplier

    # ... rest of your pipeline ...

# After human review (when it happens)
feedback_loop.record_verdict(
    finding_id=finding["id"],
    automated_verdict=fp_result["verdict"],
    human_verdict=human_decision,
    confidence=fp_result["confidence"],
    pattern_used=fp_result.get("pattern_used"),
    finding_category=finding["category"]
)
```

### Option 3: Full Integration

See `/Users/waseem.ahmed/Repos/Argus-Security/scripts/feedback_integration_example.py` for complete examples.

---

## Understanding Verdicts

### Verdict Types

**Automated Verdicts** (what the system predicted):
- `confirmed`: System thinks it's a real vulnerability
- `false_positive`: System thinks it's noise/safe
- `uncertain`: System isn't sure

**Human Verdicts** (your decision):
- `confirmed`: Real vulnerability
- `false_positive`: Not a vulnerability (safe to suppress)

### Error Types

When automated != human:

**False Negative (BAD!)**:
- Automated: `false_positive`
- Human: `confirmed`
- **Impact**: System missed a real vulnerability
- **Response**: Confidence reduced aggressively

**False Positive (tolerable)**:
- Automated: `confirmed`
- Human: `false_positive`
- **Impact**: System over-flagged (noisy but safe)
- **Response**: Confidence reduced moderately

---

## Key Metrics Explained

### Accuracy
Percentage of correct predictions: `(TP + TN) / Total`

**Target**: >85%

### Precision
When system says "FP", how often is it right: `TP / (TP + FP)`

**Target**: >90%

### Recall
Of all real FPs, how many did system catch: `TP / (TP + FN)`

**Target**: >80%

### F1 Score
Harmonic mean of precision and recall: `2 * (P * R) / (P + R)`

**Target**: >0.85

### False Negative Rate
Percentage of missed vulnerabilities: `FN / Total`

**Target**: <5% (critical!)

---

## Confidence Multiplier Strategy

### How It Works

1. **Baseline**: All patterns start at 1.0x
2. **High accuracy (>90%)**: Increase to 1.05x - 1.2x
3. **Low accuracy (<70%)**: Decrease to 0.7x - 0.85x
4. **High FN rate (>10%)**: Decrease to 0.6x - 0.8x (aggressive!)

### Example

Pattern has 95% accuracy with 50 samples:
- Current multiplier: 1.0x
- Recommended: 1.1x
- Effect: Confidence boosted from 0.80 to 0.88

Pattern has 20% false negative rate:
- Current multiplier: 1.0x
- Recommended: 0.6x
- Effect: Confidence reduced from 0.80 to 0.48

---

## Troubleshooting

### Q: "No patterns with sufficient data for tuning"

**A**: You need at least 10 samples per pattern (default). Lower threshold:
```bash
./scripts/feedback_cli.py tune --min-samples 5
```

### Q: "Accuracy is low (<70%)"

**A**: Check which patterns are problematic:
```bash
# List all patterns
cat .argus/feedback/feedback_records.jsonl | jq -r '.pattern_used' | sort | uniq

# Check each one
for pattern in $(cat .argus/feedback/feedback_records.jsonl | jq -r '.pattern_used' | sort | uniq); do
  echo "=== $pattern ==="
  ./scripts/feedback_cli.py accuracy --pattern "$pattern"
done
```

### Q: "High false negative rate - missing vulnerabilities!"

**A**: Critical issue! Immediately reduce confidence:
```python
from feedback_loop import FeedbackLoop, ConfidenceAdjustment

feedback_loop = FeedbackLoop()
feedback_loop.apply_adjustments([
    ConfidenceAdjustment(
        pattern_id="problematic_pattern",
        current_multiplier=1.0,
        recommended_multiplier=0.5,
        reasoning="Emergency: High false negative rate",
        sample_size=10,
        accuracy=0.6
    )
], dry_run=False)
```

### Q: "How do I reset everything?"

**A**: Remove feedback data:
```bash
rm -rf .argus/feedback/
# System will start fresh
```

---

## Data Storage

### Location
```
.argus/feedback/
├── feedback_records.jsonl       # All verdicts (append-only)
└── confidence_adjustments.json  # Current multipliers
```

### Backup
```bash
# Backup feedback data
tar -czf feedback_backup_$(date +%Y%m%d).tar.gz .argus/feedback/

# Restore
tar -xzf feedback_backup_20260129.tar.gz
```

### Size Management

Typical sizes:
- 1000 verdicts ≈ 200 KB
- 10,000 verdicts ≈ 2 MB

Archive old data if needed:
```bash
# Archive feedback older than 6 months
mv .argus/feedback/feedback_records.jsonl \
   .argus/feedback/feedback_records_archive_$(date +%Y%m).jsonl

# Keep confidence_adjustments.json (it's learned state)
```

---

## Best Practices

### 1. Start Small
- Record 20-30 verdicts manually
- Run first tuning
- Observe changes

### 2. Be Consistent
- Review findings regularly
- Record verdicts immediately
- Don't wait to batch them

### 3. Focus on False Negatives
- False negatives = missed vulnerabilities (BAD!)
- If you find system missed a vuln, record it immediately
- These get priority in tuning

### 4. Monitor Trends
- Check stats weekly
- Run tuning monthly
- Watch for declining accuracy

### 5. Trust but Verify
- After tuning, review a few findings
- Ensure confidence changes make sense
- Can always revert adjustments

---

## Getting Help

### View Logs
```bash
# Feedback loop uses standard logging
export ARGUS_LOG_LEVEL=DEBUG
./scripts/feedback_cli.py stats
```

### Inspect Data
```bash
# View feedback records
cat .argus/feedback/feedback_records.jsonl | jq

# View current multipliers
cat .argus/feedback/confidence_adjustments.json | jq

# Count records per pattern
cat .argus/feedback/feedback_records.jsonl | jq -r '.pattern_used' | sort | uniq -c
```

### Run Tests
```bash
pytest tests/test_feedback_loop.py -v
```

### Examples
```bash
python scripts/feedback_integration_example.py
```

---

## Next Steps

1. **Record your first 10 verdicts**
2. **Run weekly accuracy checks**
3. **Apply monthly tuning**
4. **Monitor false negative rate** (keep <5%)
5. **Integrate with your pipeline** (see examples)

For detailed documentation, see:
- `/Users/waseem.ahmed/Repos/Argus-Security/FEEDBACK_LOOP_IMPLEMENTATION.md` - Complete implementation guide
- `/Users/waseem.ahmed/Repos/Argus-Security/scripts/feedback_integration_example.py` - Integration examples
- `/Users/waseem.ahmed/Repos/Argus-Security/tests/test_feedback_loop.py` - Test suite

---

**Happy Learning!**
