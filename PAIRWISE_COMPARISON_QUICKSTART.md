# Pairwise Comparison - Quick Start Guide

## 30-Second Overview

The Pairwise Comparison Engine compares Argus findings against independent Codex analysis using AI judges to determine which tool is better.

## Prerequisites

```bash
# Set your API key
export ANTHROPIC_API_KEY="sk-ant-..."
# or for OpenAI
export OPENAI_API_KEY="sk-..."
```

## Basic Usage

```bash
python scripts/pairwise_comparison.py \
    --argus-findings argus_results.json \
    --codex-findings codex_results.json \
    --output comparison_report.json \
    --output-markdown comparison_report.md
```

## After dual_audit.py

If you ran `dual_audit.py`, findings are already available:

```bash
# Find the latest dual audit directory
LATEST=$(find .argus/dual-audit -type d -maxdepth 1 | sort | tail -1)

# Run comparison
python scripts/pairwise_comparison.py \
    --argus-findings $LATEST/argus_results.json \
    --codex-findings $LATEST/codex_validation.json \
    --output $LATEST/comparison.json \
    --output-markdown $LATEST/comparison.md
```

## Using the Example Script

```bash
bash examples/pairwise_comparison_example.sh /path/to/repo
```

This will:
1. Detect latest dual audit results
2. Run pairwise comparison
3. Display summary metrics
4. Show report preview

## Understanding Results

### Key Metrics in JSON Report

```json
{
  "aggregation": {
    "overall_winner": "argus",           // Which tool performed better
    "avg_argus_score": 4.1,              // Argus average: 1-5 scale
    "avg_codex_score": 3.8,                 // Codex average: 1-5 scale
    "argus_win_rate": 0.467,             // % of comparisons won (46.7%)
    "codex_win_rate": 0.267,                // % of comparisons won (26.7%)
    "matched_findings": 12,                 // Findings found by both tools
    "argus_only": 2,                     // Findings only Argus found
    "codex_only": 1,                        // Findings only Codex found
    "critical_by_argus": 2,              // Critical findings by Argus
    "critical_by_codex": 1,                 // Critical findings by Codex
    "avg_argus_coverage": 4.2,           // Coverage score 1-5
    "avg_argus_accuracy": 4.0,           // Accuracy score 1-5
    "avg_argus_actionability": 4.1       // Actionability score 1-5
  }
}
```

### Score Interpretation

| Score | Meaning |
|-------|---------|
| 4.5-5.0 | Excellent - Comprehensive and accurate |
| 3.5-4.4 | Good - Well-analyzed with minor gaps |
| 2.5-3.4 | Adequate - Covers basics but lacks depth |
| 1.5-2.4 | Poor - Limited or inaccurate analysis |
| 0-1.4 | Very Poor - Major issues |

## Viewing Results

### Quick Overview
```bash
# Show JSON summary
jq '.aggregation' comparison_report.json

# Show detailed metrics
cat comparison_report.json | python3 -m json.tool | head -50
```

### Human-Readable Report
```bash
# Open markdown report (formatted for reading)
cat comparison_report.md
# or with paging
less comparison_report.md
```

## Common Options

### Limit Cost (Important!)
```bash
# Only run first 10 comparisons (~$0.03)
python scripts/pairwise_comparison.py \
    --argus-findings argus.json \
    --codex-findings codex.json \
    --max-comparisons 10
```

### Use OpenAI Judge (GPT-4)
```bash
python scripts/pairwise_comparison.py \
    --argus-findings argus.json \
    --codex-findings codex.json \
    --judge-model openai
```

### Adjust Matching Threshold
```bash
# Use 0.5 instead of default 0.7 (more lenient matching)
python scripts/pairwise_comparison.py \
    --argus-findings argus.json \
    --codex-findings codex.json \
    --match-threshold 0.5
```

## Workflow Example

```bash
#!/bin/bash

# Step 1: Run dual audit (if needed)
python scripts/dual_audit.py /path/to/repo

# Step 2: Run comparison with cost limit
python scripts/pairwise_comparison.py \
    --argus-findings .argus/dual-audit/*/argus_results.json \
    --codex-findings .argus/dual-audit/*/codex_validation.json \
    --max-comparisons 20 \
    --output comparison_report.json \
    --output-markdown comparison_report.md

# Step 3: Review results
echo "=== WINNER ==="
jq '.aggregation.overall_winner' comparison_report.json

echo -e "\n=== SCORES ==="
jq '.aggregation | {argus: .avg_argus_score, codex: .avg_codex_score}' comparison_report.json

echo -e "\n=== COVERAGE ==="
jq '.aggregation | {argus_coverage: .avg_argus_coverage, codex_coverage: .avg_codex_coverage}' comparison_report.json

echo -e "\n=== Details in: comparison_report.md ==="
```

## Cost Estimates

### Anthropic Claude (Cheaper)
```
1 comparison  =  $0.003
10 comparisons = $0.03   (good for testing)
50 comparisons = $0.15
100 comparisons = $0.30
```

### OpenAI GPT-4 (More Expensive)
```
1 comparison  =  $0.008
10 comparisons = $0.08   (good for testing)
50 comparisons = $0.40
100 comparisons = $0.80
```

## What Gets Compared

For each matched finding, the judge rates:

1. **Coverage**: How comprehensive is the analysis?
2. **Accuracy**: How confident is the assessment?
3. **Actionability**: How clear are the fix steps?
4. **Detail**: Is there sufficient evidence?
5. **Risk Assessment**: Is severity appropriate?

Each rated on 1-5 scale, then winner determined.

## Interpreting Markdown Report

The markdown report includes:

1. **Executive Summary**: Winner and key metrics table
2. **Breakdown**: How many findings each tool found
3. **Detailed Comparisons**: Per-finding analysis
   - File path
   - Severity
   - Judge reasoning
   - Key differences
   - Agreement points
4. **Analysis Summary**: Overall strengths/weaknesses

## Troubleshooting

### Error: "Anthropic API key required"
```bash
export ANTHROPIC_API_KEY="your-key-here"
python scripts/pairwise_comparison.py ...
```

### Error: "No valid JSON found in response"
- Add `--max-comparisons 1` to debug
- Try `--judge-model anthropic` (more reliable)
- Check API key is valid

### Very Slow or Expensive
```bash
# Use --max-comparisons to limit
--max-comparisons 5  # Only 5 comparisons
--max-comparisons 10 # Only 10 comparisons
```

### Empty Results
- Verify findings JSON format (should have `findings` array)
- Check files are readable
- Try with small test files first

## File Format Expected

```json
{
  "findings": [
    {
      "id": "unique-id",
      "path": "src/file.py",
      "rule_id": "RULE-001",
      "severity": "high",
      "message": "Description of issue",
      "evidence": {},
      "references": [],
      "confidence": 0.95
    }
  ]
}
```

## Integration with CI/CD

### GitHub Actions
```yaml
- name: Pairwise Comparison
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
  run: |
    python scripts/pairwise_comparison.py \
      --argus-findings results/argus.json \
      --codex-findings results/codex.json \
      --max-comparisons 20 \
      --output-markdown results/comparison.md

    # Upload report as artifact
    # or post as PR comment
```

## Next Steps

1. **Read detailed guide**: See `/docs/pairwise_comparison_guide.md`
2. **View examples**: `/examples/pairwise_comparison_example.sh`
3. **Run tests**: `pytest tests/unit/test_pairwise_comparison.py`
4. **Check code**: `/scripts/pairwise_comparison.py`

## Key Commands Reference

```bash
# Basic comparison
python scripts/pairwise_comparison.py \
    --argus-findings argus.json \
    --codex-findings codex.json \
    --output report.json

# With markdown (recommended)
python scripts/pairwise_comparison.py \
    --argus-findings argus.json \
    --codex-findings codex.json \
    --output report.json \
    --output-markdown report.md

# Cost-limited (first 10)
python scripts/pairwise_comparison.py \
    --argus-findings argus.json \
    --codex-findings codex.json \
    --max-comparisons 10

# With OpenAI judge
python scripts/pairwise_comparison.py \
    --argus-findings argus.json \
    --codex-findings codex.json \
    --judge-model openai

# View results
jq '.aggregation' report.json
cat report.md
```

---

**Need help?** Check `/docs/pairwise_comparison_guide.md` for detailed documentation.
