# Feedback Loop System Implementation

## Executive Summary

This document describes the comprehensive Feedback Loop System for Argus Security's Enhanced False Positive Detector. The system learns from human TP/FP decisions and automatically adjusts confidence weights over time to improve accuracy.

**Problem Solved**: Once deployed, the FP detector never improved from real-world data. No mechanism existed to learn from human corrections.

**Solution**: A complete feedback loop system that:
- Records human verdicts (TP/FP decisions)
- Tracks pattern accuracy metrics (precision, recall, F1)
- Calculates recommended confidence adjustments
- Auto-applies tuning with safeguards
- Provides CLI tools for management

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Feedback Loop System                      │
└─────────────────────────────────────────────────────────────┘

┌──────────────┐      ┌──────────────┐      ┌──────────────┐
│  Scanner     │─────>│ FP Detector  │─────>│   Human      │
│  Finding     │      │ (w/ Feedback)│      │   Review     │
└──────────────┘      └──────────────┘      └──────────────┘
                              │                      │
                              │ Apply Multiplier     │ Record Verdict
                              │                      │
                              v                      v
                      ┌──────────────────────────────────┐
                      │     Feedback Loop Storage        │
                      │  .argus/feedback/                │
                      │  ├─ feedback_records.jsonl       │
                      │  └─ confidence_adjustments.json  │
                      └──────────────────────────────────┘
                              │
                              │ Periodic Tuning
                              v
                      ┌──────────────────────────────────┐
                      │   Calculate Adjustments          │
                      │   - Pattern accuracy             │
                      │   - Precision/Recall             │
                      │   - False negative rate          │
                      │   - Recommended multiplier       │
                      └──────────────────────────────────┘
```

---

## Components

### 1. Core Module: `feedback_loop.py`

**Purpose**: Core feedback loop engine

**Key Classes**:

- **`FeedbackRecord`**: Single feedback record
  - Tracks automated vs human verdict
  - Classifies error type (FN/FP)
  - Records confidence, pattern, timestamp

- **`PatternAccuracy`**: Pattern performance metrics
  - Confusion matrix (TP/FP/TN/FN)
  - Precision, Recall, F1 Score
  - Overall accuracy

- **`ConfidenceAdjustment`**: Recommended tuning
  - Current vs recommended multiplier
  - Reasoning for adjustment
  - Sample size and accuracy

- **`FeedbackLoop`**: Main controller
  - Records verdicts
  - Calculates metrics
  - Suggests adjustments
  - Applies tuning

**Storage**:
```
.argus/feedback/
├── feedback_records.jsonl       # All verdicts (append-only)
└── confidence_adjustments.json  # Current multipliers
```

---

### 2. CLI Tool: `feedback_cli.py`

**Purpose**: Command-line interface for feedback management

**Commands**:

```bash
# Record human verdict
./scripts/feedback_cli.py record \
  --finding-id semgrep-001 \
  --automated false_positive \
  --human confirmed \
  --confidence 0.75 \
  --pattern oauth2_localhost_pattern \
  --category oauth2 \
  --reasoning "Actually vulnerable"

# Show overall statistics
./scripts/feedback_cli.py stats

# Show pattern-specific accuracy
./scripts/feedback_cli.py accuracy --pattern oauth2_localhost_pattern

# Suggest confidence adjustments (dry-run)
./scripts/feedback_cli.py tune --min-samples 10

# Apply adjustments
./scripts/feedback_cli.py tune --min-samples 10 --apply
```

**Output Examples**:

```bash
$ ./scripts/feedback_cli.py stats
Total records: 127
Accuracy: 82.7%
False negatives: 8
False positives: 14
Patterns tracked: 12

$ ./scripts/feedback_cli.py accuracy --pattern oauth2_localhost_pattern
Pattern: oauth2_localhost_pattern
Samples: 45
Accuracy: 88.9%
Precision: 92.3%
Recall: 85.7%
F1 Score: 0.89

$ ./scripts/feedback_cli.py tune --min-samples 10
Found 8 patterns with sufficient data:

Pattern: oauth2_localhost_pattern
  Current: 1.00
  Recommended: 1.05
  Samples: 45
  Reasoning: Accuracy: 88.9% (45 samples) | Precision: 92.3%, Recall: 85.7% | High accuracy - can increase confidence

Pattern: file_permission_777_pattern
  Current: 1.00
  Recommended: 0.70
  Samples: 32
  Reasoning: Accuracy: 62.5% (32 samples) | Precision: 60.0%, Recall: 66.7% | Low accuracy - reducing confidence

Run with --apply to apply these adjustments
```

---

### 3. Integration Example: `feedback_integration_example.py`

**Purpose**: Shows how to integrate with existing pipeline

**Key Features**:

1. **Apply learned multipliers during detection**
```python
integration = FeedbackIntegration()
result = integration.analyze_with_feedback(finding)
# Confidence automatically adjusted based on learned patterns
```

2. **Record human verdicts**
```python
integration.record_human_review(
    finding_id="semgrep-001",
    automated_result=result,
    human_verdict="false_positive",
    reasoning="Confirmed safe"
)
```

3. **Periodic tuning**
```python
# Run weekly/monthly
adjustments = integration.periodic_tuning(
    min_samples=10,
    auto_apply=True
)
```

---

### 4. Test Suite: `test_feedback_loop.py`

**Purpose**: Comprehensive test coverage

**Test Classes**:

- `TestFeedbackRecord`: Dataclass validation
- `TestPatternAccuracy`: Metrics calculation
- `TestFeedbackLoop`: Core functionality
  - Recording verdicts
  - Calculating accuracy
  - Suggesting adjustments
  - Applying tuning
  - End-to-end workflow

**Run Tests**:
```bash
pytest tests/test_feedback_loop.py -v
```

---

## Confidence Adjustment Algorithm

The system uses a **security-first** approach when adjusting confidence multipliers:

### Adjustment Strategy

```python
if false_negative_rate > 20%:
    # CRITICAL: Missing real vulnerabilities!
    multiplier = max(current * 0.6, 0.5)  # Aggressive reduction

elif false_negative_rate > 10%:
    # High false negatives
    multiplier = max(current * 0.8, 0.7)

elif accuracy >= 95%:
    # Excellent accuracy
    multiplier = min(current * 1.1, 1.2)  # Increase confidence

elif accuracy >= 90%:
    # Very good accuracy
    multiplier = min(current * 1.05, 1.1)

elif accuracy >= 70%:
    # Acceptable
    multiplier = current  # No change

else:
    # Poor accuracy
    multiplier = max(current * 0.85, 0.7)
```

### Key Principles

1. **Security-first**: Prioritize reducing false negatives over false positives
2. **Conservative increases**: Only increase confidence for proven patterns (>90% accuracy)
3. **Aggressive decreases**: Rapidly reduce confidence for patterns missing vulnerabilities
4. **Bounded adjustments**: Multipliers capped at [0.5, 1.2]

---

## Usage Guide

### Initial Setup

1. **Install dependencies** (already included in Argus Security):
```bash
# No additional dependencies required
```

2. **Initialize feedback directory**:
```bash
mkdir -p .argus/feedback
```

### Daily Operations

#### 1. Scan with Feedback-Adjusted Detection

```python
from feedback_integration_example import FeedbackIntegration

integration = FeedbackIntegration()

# Analyze finding
result = integration.analyze_with_feedback(finding)

if result['verdict'] == 'false_positive' and result['confidence'] > 0.8:
    # Suppress with high confidence
    suppress_finding(finding)
```

#### 2. Record Human Reviews

**Option A: Via CLI**
```bash
./scripts/feedback_cli.py record \
  --finding-id "$FINDING_ID" \
  --automated "$AUTOMATED_VERDICT" \
  --human "$HUMAN_VERDICT" \
  --confidence "$CONFIDENCE" \
  --pattern "$PATTERN_ID" \
  --category "$CATEGORY"
```

**Option B: Via Python**
```python
integration.record_human_review(
    finding_id="semgrep-oauth2-042",
    automated_result=automated_result,
    human_verdict="false_positive",
    reasoning="Confirmed: dev configuration"
)
```

#### 3. Monitor Statistics

```bash
# Check overall accuracy
./scripts/feedback_cli.py stats

# Check specific pattern
./scripts/feedback_cli.py accuracy --pattern oauth2_localhost_pattern
```

### Weekly/Monthly Tuning

Run periodic tuning to update confidence multipliers:

```bash
# 1. Preview adjustments (dry-run)
./scripts/feedback_cli.py tune --min-samples 10

# 2. Review and apply
./scripts/feedback_cli.py tune --min-samples 10 --apply
```

**Recommended Schedule**:
- **Weekly**: Review statistics and high false-negative patterns
- **Monthly**: Run full tuning with adjustments
- **Quarterly**: Audit pattern performance and retire poor patterns

---

## Integration with Enhanced FP Detector

### Step 1: Load Confidence Multipliers

Add to `enhanced_fp_detector.py`:

```python
from feedback_loop import FeedbackLoop

class EnhancedFalsePositiveDetector:
    def __init__(self):
        self.feedback_loop = FeedbackLoop()
        # ... existing init

    def analyze(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        # ... existing analysis logic

        # Apply learned confidence multiplier
        if result.get("pattern_used"):
            multiplier = self.feedback_loop._get_current_multiplier(
                result["pattern_used"]
            )
            result["original_confidence"] = result["confidence"]
            result["confidence"] = min(result["confidence"] * multiplier, 1.0)
            result["confidence_multiplier"] = multiplier

        return result
```

### Step 2: Record Verdicts in Pipeline

Add to `run_ai_audit.py` or wherever human review happens:

```python
from feedback_loop import FeedbackLoop

# After human review
feedback_loop = FeedbackLoop()
feedback_loop.record_verdict(
    finding_id=finding["id"],
    automated_verdict=automated_result["verdict"],
    human_verdict=human_verdict,
    confidence=automated_result["confidence"],
    pattern_used=automated_result.get("pattern_used"),
    finding_category=finding.get("category", "unknown"),
    reasoning=human_reasoning
)
```

### Step 3: Automated Tuning (Optional)

Add to CI/CD or scheduled job:

```bash
# Weekly tuning job
#!/bin/bash
cd /path/to/argus-security

# Check if enough new data
RECORDS=$(./scripts/feedback_cli.py stats | grep "Total records" | awk '{print $3}')

if [ "$RECORDS" -ge 50 ]; then
  echo "Running feedback loop tuning..."
  ./scripts/feedback_cli.py tune --min-samples 10 --apply

  # Commit updated adjustments
  git add .argus/feedback/confidence_adjustments.json
  git commit -m "chore: Update FP detector confidence from feedback"
  git push
fi
```

---

## Data Privacy & Security

### What Gets Stored

**feedback_records.jsonl**:
```json
{
  "finding_id": "semgrep-001",
  "automated_verdict": "false_positive",
  "human_verdict": "confirmed",
  "confidence": 0.75,
  "pattern_used": "oauth2_localhost_pattern",
  "finding_category": "oauth2",
  "timestamp": "2026-01-29T10:30:00",
  "reasoning": "Actually vulnerable",
  "is_correct": false,
  "error_type": "false_negative"
}
```

**NO sensitive data included**:
- No source code
- No secrets
- No file paths (only finding_id reference)
- No company-specific details

### Access Control

```bash
# Restrict access to feedback directory
chmod 700 .argus/feedback

# Only store in private repos
echo ".argus/feedback/" >> .gitignore  # If needed
```

---

## Metrics & Monitoring

### Key Metrics to Track

1. **Overall Accuracy**: `correct / total_records`
   - Target: >85%

2. **False Negative Rate**: `false_negatives / total_records`
   - Target: <5% (security-critical!)

3. **False Positive Rate**: `false_positives / total_records`
   - Target: <15%

4. **Pattern-Specific Accuracy**: Per suppression pattern
   - Target: >80% per pattern

5. **Coverage**: Patterns with sufficient data
   - Target: >10 samples per pattern

### Monitoring Dashboard (Example)

```python
def generate_dashboard():
    feedback_loop = FeedbackLoop()
    stats = feedback_loop.get_statistics()

    print("=== Feedback Loop Dashboard ===\n")
    print(f"Total Records: {stats['total_records']}")
    print(f"Overall Accuracy: {stats['accuracy']:.1%}")
    print(f"False Negatives: {stats['false_negatives']} "
          f"({stats['false_negatives']/stats['total_records']:.1%})")
    print(f"False Positives: {stats['false_positives']} "
          f"({stats['false_positives']/stats['total_records']:.1%})")
    print(f"Patterns Tracked: {stats['patterns_tracked']}")

    # Pattern breakdown
    print("\n=== Pattern Performance ===")
    patterns = feedback_loop._get_all_patterns()
    for pattern_id, pattern_name in patterns.items():
        accuracy = feedback_loop.calculate_pattern_accuracy(pattern_id, pattern_name)
        if accuracy.total_samples >= 5:
            print(f"\n{pattern_name}:")
            print(f"  Samples: {accuracy.total_samples}")
            print(f"  Accuracy: {accuracy.accuracy:.1%}")
            print(f"  F1 Score: {accuracy.f1_score:.2f}")
```

---

## Troubleshooting

### Issue: Low Overall Accuracy (<70%)

**Diagnosis**:
```bash
./scripts/feedback_cli.py stats
# Check false negative vs false positive ratio
```

**Solutions**:
- If high FN rate: Patterns too aggressive, reduce multipliers
- If high FP rate: Patterns too conservative, may need better patterns
- Review individual pattern accuracy to find culprits

### Issue: Pattern Not Getting Adjusted

**Diagnosis**:
```bash
./scripts/feedback_cli.py accuracy --pattern <pattern_id>
# Check sample count
```

**Solutions**:
- Need minimum 10 samples (default)
- Lower threshold: `tune --min-samples 5`
- Record more verdicts for that pattern

### Issue: Confidence Multiplier Not Applied

**Diagnosis**:
```python
feedback_loop = FeedbackLoop()
multiplier = feedback_loop._get_current_multiplier("pattern_id")
print(f"Current multiplier: {multiplier}")
```

**Solutions**:
- Verify adjustments file exists: `.argus/feedback/confidence_adjustments.json`
- Check pattern ID matches exactly
- Ensure `apply_adjustments()` was called with `dry_run=False`

### Issue: Too Many False Negatives

**Critical issue** - missing real vulnerabilities!

**Immediate Actions**:
1. Manually review recent false negatives
2. Identify problematic patterns
3. Reduce their multipliers immediately:

```python
feedback_loop = FeedbackLoop()
feedback_loop.apply_adjustments([
    ConfidenceAdjustment(
        pattern_id="problematic_pattern",
        current_multiplier=1.0,
        recommended_multiplier=0.6,
        reasoning="High false negative rate",
        sample_size=20,
        accuracy=0.65
    )
], dry_run=False)
```

---

## Performance Considerations

### Storage

- **feedback_records.jsonl**: ~200 bytes per record
  - 1000 records ≈ 200 KB
  - 10,000 records ≈ 2 MB
- **confidence_adjustments.json**: ~150 bytes per pattern
  - 50 patterns ≈ 7.5 KB

**Rotation Strategy** (if needed):
```bash
# Archive old feedback (>6 months)
mv .argus/feedback/feedback_records.jsonl \
   .argus/feedback/feedback_records_archive_2026Q1.jsonl

# Start fresh (confidence_adjustments.json preserved)
```

### Computational Cost

- **Recording verdict**: O(1) - append to file
- **Calculate accuracy**: O(n) per pattern - linear scan
- **Suggest adjustments**: O(p*n) where p=patterns, n=records
  - Typically <100ms for 1000 records

**Optimization** (if needed):
- Index by pattern_id
- Cache accuracy calculations
- Limit to recent records (e.g., last 6 months)

---

## Future Enhancements

### 1. Pattern Auto-Discovery

Learn new patterns from human corrections:

```python
# Analyze false negatives to discover missed patterns
def discover_new_patterns(false_negatives):
    # Extract common features
    # Generate new suppression rules
    # Test on historical data
    pass
```

### 2. Multi-Model A/B Testing

Test different confidence adjustment strategies:

```python
strategies = ["conservative", "balanced", "aggressive"]
# Split findings across strategies
# Measure accuracy per strategy
# Use best performer
```

### 3. Explainable Adjustments

Generate detailed reports on why confidence changed:

```python
def explain_adjustment(pattern_id):
    """Generate human-readable explanation of adjustment"""
    # Show examples of TP/FP decisions
    # Highlight what changed
    # Recommend pattern improvements
    pass
```

### 4. Integration with GitHub Issues

Automatically create issues for patterns with high FN rates:

```python
def create_pattern_issue(pattern_id, accuracy):
    """Create GitHub issue for problematic pattern"""
    issue_body = f"""
    Pattern `{pattern_id}` has high false negative rate!

    Current Stats:
    - Accuracy: {accuracy.accuracy:.1%}
    - False Negatives: {accuracy.false_negatives}
    - Samples: {accuracy.total_samples}

    Action: Review and improve this pattern
    """
    # Create GitHub issue
```

---

## Summary

The Feedback Loop System provides:

1. **Continuous Learning**: System improves from human decisions
2. **Automated Tuning**: Confidence weights adjust over time
3. **Security-First**: Prioritizes reducing false negatives
4. **Easy Integration**: Minimal changes to existing pipeline
5. **Full Observability**: CLI tools and metrics
6. **Production-Ready**: Comprehensive tests and safeguards

**Key Files**:
- `/Users/waseem.ahmed/Repos/Argus-Security/scripts/feedback_loop.py` - Core engine
- `/Users/waseem.ahmed/Repos/Argus-Security/scripts/feedback_cli.py` - CLI management tool
- `/Users/waseem.ahmed/Repos/Argus-Security/scripts/feedback_integration_example.py` - Integration examples
- `/Users/waseem.ahmed/Repos/Argus-Security/tests/test_feedback_loop.py` - Test suite

**Next Steps**:
1. Run test suite: `pytest tests/test_feedback_loop.py -v`
2. Try examples: `python scripts/feedback_integration_example.py`
3. Integrate with Enhanced FP Detector
4. Set up periodic tuning job (weekly/monthly)
5. Monitor metrics and adjust as needed

---

## Quick Reference

```bash
# Record verdict
./scripts/feedback_cli.py record --finding-id ID --automated VERDICT --human VERDICT --confidence 0.8 --pattern PATTERN --category CATEGORY

# Show stats
./scripts/feedback_cli.py stats

# Show pattern accuracy
./scripts/feedback_cli.py accuracy --pattern PATTERN_ID

# Tune confidence (dry-run)
./scripts/feedback_cli.py tune --min-samples 10

# Apply tuning
./scripts/feedback_cli.py tune --min-samples 10 --apply

# Run tests
pytest tests/test_feedback_loop.py -v

# Run examples
python scripts/feedback_integration_example.py
```

---

**Documentation Version**: 1.0
**Last Updated**: 2026-01-29
**Author**: Argus Security Team
