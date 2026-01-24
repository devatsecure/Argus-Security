# Pairwise Comparison Analysis Guide

## Overview

The **Pairwise Comparison Engine** evaluates Argus findings against independent Codex analysis using AI-powered judges. It determines which analysis is better for each finding and aggregates results to identify overall strengths and weaknesses of each tool.

## Key Features

### 1. **Pairwise Evaluation**
- Compares findings from Argus (Anthropic Claude) with Codex (OpenAI) independent analysis
- Matches findings based on similarity (file path, rule ID, severity, message)
- Handles both matched and unmatched findings

### 2. **Direct Comparison Prompts**
- AI judge receives detailed information about both analyses
- Judge evaluates coverage, accuracy, actionability, detail, and risk assessment
- Judge provides detailed reasoning for comparisons

### 3. **Scoring System**
- 1-5 scale rating for each dimension:
  - **Coverage**: How comprehensive is the analysis?
  - **Accuracy**: How confident is the assessment?
  - **Actionability**: How clear are remediation steps?
  - **Detail**: Is there sufficient evidence?
  - **Risk Assessment**: Is severity appropriate?

### 4. **Preference Aggregation**
- Calculates win rates and preferences
- Aggregates scores across all comparisons
- Identifies overall winner based on scoring
- Provides detailed statistics

### 5. **Detailed Reasoning**
- Captures judge's explanation for each comparison
- Records key differences between analyses
- Documents areas of agreement and disagreement
- Tracks confidence levels

## Architecture

### Core Components

#### FindingMatcher
Matches findings between two sets using similarity scoring:
- File path matching (weight: 0.3)
- Rule/category matching (weight: 0.3)
- Severity matching (weight: 0.2)
- Message/description similarity (weight: 0.2)

**Match threshold**: 0.7 (configurable, 70% similarity required)

#### PairwiseJudge
AI-powered evaluator using Claude or GPT-4:
- Builds detailed comparison prompts
- Scores findings on multiple dimensions
- Parses JSON responses reliably
- Handles both matched and unmatched findings
- Includes retry logic for robustness

#### PairwiseComparator
Main orchestrator that:
1. Matches findings between Argus and Codex
2. Runs judge comparisons on matched pairs
3. Evaluates unmatched findings
4. Aggregates all results

#### ComparisonReportGenerator
Creates detailed reports:
- JSON report with full data
- Markdown report with human-readable analysis
- Formatted comparisons
- Statistical summaries

### Data Structures

#### PairwiseComparison
Individual comparison result:
```python
@dataclass
class PairwiseComparison:
    finding_id: str
    argus_finding: Optional[Dict]
    codex_finding: Optional[Dict]
    match_type: str  # matched, argus_only, codex_only
    argus_score: int  # 1-5
    codex_score: int  # 1-5
    winner: str  # argus, codex, tie
    judge_reasoning: str
    key_differences: List[str]
    agreement_aspects: List[str]
    disagreement_aspects: List[str]
    coverage_score: float
    accuracy_score: float
    actionability_score: float
    confidence: float  # 0-1
```

#### PairwiseAggregation
Aggregated statistics:
```python
@dataclass
class PairwiseAggregation:
    total_comparisons: int
    matched_findings: int
    argus_only: int
    codex_only: int
    argus_wins: int
    codex_wins: int
    ties: int
    avg_argus_score: float
    avg_codex_score: float
    overall_winner: str
    recommendation: str
    # + 10+ more aggregated metrics
```

## Usage

### Basic Usage

```bash
python scripts/pairwise_comparison.py \
    --argus-findings argus_results.json \
    --codex-findings codex_results.json \
    --output comparison_report.json
```

### With Markdown Report

```bash
python scripts/pairwise_comparison.py \
    --argus-findings argus_results.json \
    --codex-findings codex_results.json \
    --output comparison_report.json \
    --output-markdown comparison_report.md
```

### With OpenAI Judge (GPT-4)

```bash
python scripts/pairwise_comparison.py \
    --argus-findings argus_results.json \
    --codex-findings codex_results.json \
    --judge-model openai \
    --output comparison_report.json
```

### With Cost Limiting

```bash
# Only run first 10 comparisons
python scripts/pairwise_comparison.py \
    --argus-findings argus_results.json \
    --codex-findings codex_results.json \
    --max-comparisons 10 \
    --output comparison_report.json
```

### Custom Match Threshold

```bash
# Use 0.8 threshold (80% similarity required)
python scripts/pairwise_comparison.py \
    --argus-findings argus_results.json \
    --codex-findings codex_results.json \
    --match-threshold 0.8 \
    --output comparison_report.json
```

## Command-Line Options

| Option | Required | Default | Description |
|--------|----------|---------|-------------|
| `--argus-findings` | Yes | N/A | Path to Argus findings JSON |
| `--codex-findings` | Yes | N/A | Path to Codex findings JSON |
| `--output` | No | `pairwise_comparison_report.json` | Output file for JSON report |
| `--output-markdown` | No | N/A | Optional markdown report path |
| `--judge-model` | No | `anthropic` | Judge model: `anthropic` or `openai` |
| `--match-threshold` | No | `0.7` | Finding match threshold (0-1) |
| `--max-comparisons` | No | N/A | Max comparisons to run (cost limit) |

## Integration with dual_audit.py

The pairwise comparison should be run after `dual_audit.py` completes:

```bash
# Step 1: Run dual audit
python scripts/dual_audit.py /path/to/repo --project-type backend-api

# Step 2: Run pairwise comparison
python scripts/pairwise_comparison.py \
    --argus-findings .argus/dual-audit/20250114-120000/argus_results.json \
    --codex-findings .argus/dual-audit/20250114-120000/codex_validation.json \
    --output-markdown .argus/dual-audit/20250114-120000/pairwise_comparison.md
```

## Output Format

### JSON Report Structure

```json
{
  "generated_at": "2025-01-14T12:30:45.123Z",
  "aggregation": {
    "total_comparisons": 15,
    "matched_findings": 12,
    "argus_only": 2,
    "codex_only": 1,
    "argus_wins": 7,
    "codex_wins": 4,
    "ties": 4,
    "avg_argus_score": 4.1,
    "avg_codex_score": 3.8,
    "overall_winner": "argus",
    "recommendation": "Argus provided superior analysis..."
  },
  "comparisons": [
    {
      "finding_id": "finding_001",
      "match_type": "matched",
      "argus_score": 5,
      "codex_score": 4,
      "winner": "argus",
      "judge_reasoning": "...",
      "confidence": 0.95
    },
    ...
  ]
}
```

### Markdown Report Structure

The markdown report includes:
1. **Executive Summary**: Overall winner and key metrics table
2. **Comparison Breakdown**: Statistics on matched/unmatched findings
3. **Detailed Comparisons**: Individual comparison details
4. **Analysis Summary**: Strengths/weaknesses analysis

## Scoring Interpretation

### Average Score Interpretation (1-5 scale)

| Score | Interpretation |
|-------|-----------------|
| 4.5-5.0 | Excellent - Comprehensive, accurate, actionable |
| 3.5-4.4 | Good - Well-analyzed with minor gaps |
| 2.5-3.4 | Adequate - Covers basics but lacks depth |
| 1.5-2.4 | Poor - Limited analysis or accuracy concerns |
| 0-1.4 | Very Poor - Inadequate or incorrect analysis |

### Win Rate Interpretation

| Win Rate | Interpretation |
|----------|-----------------|
| >60% | Clear winner - Significantly better performance |
| 50-60% | Slight advantage - Minor preference |
| <50% | Losing - Performs worse overall |

## Key Metrics Explained

### Coverage Score
Measures how comprehensively each analysis explains the issue:
- Does it explain the vulnerability?
- Is the impact/scope clear?
- Are multiple angles covered?

### Accuracy Score
Measures confidence that the finding is correct:
- Is this a real vulnerability or false positive?
- Is the severity assessment justified?
- Are there contradictions in the analysis?

### Actionability Score
Measures how clear the remediation is:
- Are fix steps provided?
- Is the path forward clear?
- Can developer act on this?

### Confidence
Judge's confidence in the comparison (0-1):
- High (>0.8): Clear winner
- Medium (0.5-0.8): Some ambiguity
- Low (<0.5): Unable to determine

## Advanced Usage

### Finding Filtering

To compare specific finding types, create filtered input files:

```python
import json

# Filter for high-severity findings
with open('argus_results.json') as f:
    data = json.load(f)

high_sev = [f for f in data['findings'] if f['severity'] in ['high', 'critical']]

with open('argus_high_severity.json', 'w') as f:
    json.dump({'findings': high_sev}, f)

# Then run comparison
```

### Batch Comparisons

Create a script to run multiple comparisons:

```bash
#!/bin/bash

for repo in repo1 repo2 repo3; do
    echo "Comparing $repo..."
    python scripts/pairwise_comparison.py \
        --argus-findings $repo/argus_results.json \
        --codex-findings $repo/codex_results.json \
        --output $repo/comparison_report.json \
        --output-markdown $repo/comparison_report.md
done
```

### Cost Analysis

Track costs when using different judge models:

- **Anthropic Claude**: ~$0.003 per comparison
- **OpenAI GPT-4**: ~$0.008 per comparison

With `--max-comparisons`:
- 10 comparisons: ~$0.03-$0.08
- 50 comparisons: ~$0.15-$0.40
- 100 comparisons: ~$0.30-$0.80

## Error Handling

The script includes robust error handling:

1. **Missing Files**: Clear error messages with paths
2. **JSON Parsing**: Gracefully handles malformed JSON
3. **LLM Failures**: Retries with exponential backoff (up to 3 attempts)
4. **API Errors**: Logs errors and continues with neutral comparisons

### Retry Logic

Failed comparisons automatically retry with:
- Initial delay: 4 seconds
- Exponential backoff: doubles each retry
- Max attempts: 3
- Max delay: 10 seconds

### Partial Failures

If some comparisons fail, the script:
1. Logs detailed error information
2. Adds neutral comparison to results
3. Continues with remaining comparisons
4. Generates reports with available data

## Best Practices

### 1. Use Consistent Formats
Ensure both findings files use the same JSON structure:
```python
{
  "findings": [
    {
      "id": "...",
      "path": "...",
      "rule_id": "...",
      "severity": "...",
      "message": "...",
      ...
    }
  ]
}
```

### 2. Start with Sample Data
Test with small finding sets before large runs:
```bash
# Test with first 5 findings
python scripts/pairwise_comparison.py \
    --argus-findings argus.json \
    --codex-findings codex.json \
    --max-comparisons 5
```

### 3. Combine with Context
Run on specific project types:
- Backend APIs: Focus on injection, secrets
- Frontend: Focus on XSS, CSRF
- Infrastructure: Focus on IAC misconfigurations

### 4. Review Human-Readable Reports
Always review markdown report before acting on results

### 5. Track Changes Over Time
Compare reports across different versions/branches

## Troubleshooting

### Issue: "No valid JSON found in response"
**Cause**: Judge LLM returned non-JSON response
**Solution**:
- Check API keys are valid
- Try with `--judge-model anthropic` (more reliable)
- Add `--max-comparisons 1` to debug

### Issue: "Anthropic API key required"
**Cause**: Missing ANTHROPIC_API_KEY environment variable
**Solution**:
```bash
export ANTHROPIC_API_KEY="your-key-here"
python scripts/pairwise_comparison.py ...
```

### Issue: "OpenAI API error"
**Cause**: Missing OPENAI_API_KEY or invalid model
**Solution**:
```bash
export OPENAI_API_KEY="your-key-here"
python scripts/pairwise_comparison.py --judge-model openai ...
```

### Issue: Empty Results
**Cause**: Findings don't match the expected format
**Solution**: Verify JSON structure and check logs for details

### Issue: High Match Threshold Matching Nothing
**Cause**: `--match-threshold` too high (findings aren't similar enough)
**Solution**: Lower the threshold (e.g., from 0.7 to 0.5)

## Performance Characteristics

| Operation | Time | Cost |
|-----------|------|------|
| Load findings | <1 sec | $0 |
| Match findings | 1-2 sec | $0 |
| Compare 1 finding | 2-5 sec | $0.01 |
| Compare 10 findings | 20-50 sec | $0.10 |
| Compare 50 findings | 2-5 min | $0.50 |
| Generate reports | <1 sec | $0 |

## Integration Examples

### With GitHub Actions

```yaml
- name: Run Pairwise Comparison
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
  run: |
    python scripts/pairwise_comparison.py \
      --argus-findings results/argus.json \
      --codex-findings results/codex.json \
      --output results/comparison.json \
      --output-markdown results/comparison.md
```

### With Jenkins Pipeline

```groovy
stage('Pairwise Comparison') {
    steps {
        sh '''
            python scripts/pairwise_comparison.py \
                --argus-findings argus.json \
                --codex-findings codex.json \
                --output comparison_report.json
        '''
        archiveArtifacts 'comparison_report.json'
    }
}
```

### With Python Code

```python
from pairwise_comparison import (
    PairwiseComparator,
    FindingMatcher,
    PairwiseJudge
)

# Load findings
argus_findings = load_findings('argus.json')
codex_findings = load_findings('codex.json')

# Run comparison
comparator = PairwiseComparator(
    argus_findings,
    codex_findings,
    judge_model='anthropic'
)
aggregation = comparator.run_comparison()

# Access results
print(f"Winner: {aggregation.overall_winner}")
print(f"Argus Score: {aggregation.avg_argus_score:.1f}")
print(f"Codex Score: {aggregation.avg_codex_score:.1f}")
```

## Future Enhancements

Potential improvements for future versions:

1. **Parallel Judging**: Run multiple comparisons concurrently
2. **Custom Scoring Weights**: Let users define scoring importance
3. **Evidence-Based Matching**: Match on actual code location, not just metadata
4. **Exploit Validation**: Integrate sandbox validation for scoring
5. **Historical Tracking**: Track comparison results over time
6. **Dashboard Integration**: Visualize results in web dashboard
7. **Multi-Judge Consensus**: Use multiple judges for consensus
8. **Fine-tuning**: Train models on historical comparison data

## Related Documentation

- [Dual Audit Guide](./dual_audit_guide.md) - Running Argus + Codex
- [Finding Normalization](./normalizer_guide.md) - Understanding finding format
- [Provider Integration](./provider_guide.md) - LLM provider details
- [Architecture Overview](./architecture/overview.md) - System design

## Support

For issues or questions:
1. Check troubleshooting section above
2. Review logs with `--debug` flag
3. Open GitHub issue with:
   - Command used
   - Error message
   - Sample findings files (anonymized)
   - Python/env details
