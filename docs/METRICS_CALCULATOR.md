# Metrics Calculator Documentation

## Overview

The Metrics Calculator is a Python module for analyzing inter-rater agreement between security findings from two different sources (e.g., Argus and Codex). It provides sophisticated statistical analysis including Cohen's Kappa, Precision/Recall metrics, confusion matrices, and severity/category breakdowns.

**Module Location:** `/scripts/metrics_calculator.py`
**Test Suite:** `/scripts/test_metrics_calculator.py`
**Examples:** `/examples/metrics_calculator_example.py`

## Features

### 1. Cohen's Kappa Calculator
- Measures inter-rater agreement on a scale of -1 to 1
- Includes 95% confidence intervals and p-values
- Automatic interpretation (Poor, Slight, Fair, Moderate, Substantial, Almost Perfect)
- Handles different contingency table sizes

**Formula:**
```
κ = (P_o - P_e) / (1 - P_e)

where:
  P_o = observed agreement probability
  P_e = expected agreement by chance
```

### 2. Precision/Recall Metrics
Comprehensive detection metrics:
- **Precision** (TP / (TP + FP)): What % of findings are actually true
- **Recall** (TP / (TP + FN)): What % of actual findings are detected
- **F1-Score**: Harmonic mean of precision and recall
- **Accuracy**: (TP + TN) / Total
- **Specificity** (TN / (TN + FP)): True negative rate
- **False Positive Rate** (FP / (FP + TN)): Type I error rate
- **False Negative Rate** (FN / (FN + TP)): Type II error rate

### 3. Finding Matching
Intelligent matching algorithm based on:
- Path matching (40% weight)
- Line number matching (20% weight)
- Rule ID matching (20% weight)
- Severity matching (10% weight)
- Category matching (10% weight)

Threshold: 0.7+ similarity score for confirmed match

### 4. Agreement Analysis by Category
Breakdown agreement metrics by:
- **Severity Levels**: critical, high, medium, low, info
- **Finding Categories**: SAST, SECRETS, DEPS, IAC, FUZZ, RUNTIME

Includes kappa coefficient and agreement percentage for each category.

### 5. Confusion Matrix
Standard 2x2 confusion matrix:
```
                 Codex Found    Codex Missed
Argus Found   True Positive  False Positive
Argus Missed  False Negative True Negative
```

### 6. Statistical Significance Testing
- **Chi-Square Test**: Measures association in contingency table
- **P-values**: Two-tailed significance testing
- **Confidence Intervals**: 95% CI for Cohen's Kappa

## Data Structures

### MetricsReport
Complete analysis results containing:
```python
@dataclass
class MetricsReport:
    timestamp: str                              # ISO timestamp
    argus_finding_count: int                 # Total Argus findings
    codex_finding_count: int                    # Total Codex findings
    total_matches: int                          # Matched findings
    total_unique_to_argus: int              # Argus only findings
    total_unique_to_codex: int                 # Codex only findings
    simple_agreement_rate: float                # % of findings that matched
    cohens_kappa: CohenKappaResult             # Kappa with CI and p-value
    precision_recall: PrecisionRecallMetrics   # All PR metrics
    confusion_matrix: ConfusionMatrix          # TP/FP/FN/TN
    severity_agreements: list[SeverityAgreement]   # Per-severity breakdown
    category_agreements: list[CategoryAgreement]   # Per-category breakdown
    finding_matches: list[FindingMatch]        # Individual match details
    chi_square_statistic: float                # χ² test statistic
    chi_square_p_value: float                  # χ² test p-value
    severity_distribution: dict                # For visualization
    category_distribution: dict                # For visualization
```

### Finding Format
Expected input format for findings:
```json
{
  "path": "src/auth.py",           # File path
  "line": 42,                      # Line number
  "rule_id": "SEC-001",            # Rule identifier
  "rule_name": "SQL Injection",    # Human-readable name
  "severity": "critical",          # critical|high|medium|low|info
  "category": "SAST",              # SAST|SECRETS|DEPS|IAC|FUZZ|RUNTIME
  "cvss": 9.8,                     # CVSS score (optional)
  "cwe": "CWE-89",                 # CWE reference (optional)
  "evidence": {...}                # Additional evidence (optional)
}
```

## Usage

### Basic Usage

```python
from metrics_calculator import MetricsCalculator

# Load findings
argus_findings = [...]  # List of findings from Argus
codex_findings = [...]     # List of findings from Codex

# Create calculator
calculator = MetricsCalculator()

# Run comparison
report = calculator.compare_findings(argus_findings, codex_findings)

# Access results
print(f"Cohen's Kappa: {report.cohens_kappa.kappa:.3f}")
print(f"Precision: {report.precision_recall.precision:.3f}")
print(f"Agreement Rate: {report.simple_agreement_rate:.1%}")
```

### Loading from Files

```python
from metrics_calculator import load_findings_from_file, save_metrics_report

# Load findings from JSON
argus = load_findings_from_file("argus_findings.json")
codex = load_findings_from_file("codex_findings.json")

# Compare
report = calculator.compare_findings(argus, codex)

# Save report
save_metrics_report(report, "metrics_report.json")
```

### Command-Line Usage

```bash
python scripts/metrics_calculator.py \
  --argus-file argus_findings.json \
  --codex-file codex_findings.json \
  --output-file metrics_report.json
```

## Interpretation Guide

### Cohen's Kappa Scale (Landis & Koch 1977)

| Kappa Range | Interpretation |
|-------------|-----------------|
| < 0.0      | Poor            |
| 0.0 - 0.2  | Slight          |
| 0.2 - 0.4  | Fair            |
| 0.4 - 0.6  | Moderate        |
| 0.6 - 0.8  | Substantial     |
| 0.8 - 1.0  | Almost Perfect  |

### Example Interpretations

**κ = 0.85 (Substantial Agreement)**
- Two security scanners have substantial agreement on findings
- Confidence Interval: [0.82, 0.88]
- P-value: < 0.0001 (statistically significant)
- Conclusion: Scanners are in good agreement; use one as backup

**κ = 0.45 (Moderate Agreement)**
- Scanners have moderate agreement
- Some systematic differences exist
- Recommendation: Investigate disagreement sources
- Consider fine-tuning configurations

**κ = 0.15 (Slight Agreement)**
- Very low agreement
- Scanners find mostly different findings
- Recommendation: Use both scanners complementarily
- Each catches unique vulnerabilities

## Practical Examples

### Example 1: Comparing Two Security Scanners

```python
calculator = MetricsCalculator()

argus_findings = [
    {"path": "auth.py", "line": 42, "rule_id": "SQL-001",
     "severity": "critical", "category": "SAST"},
    {"path": "config.py", "line": 8, "rule_id": "SECRET-001",
     "severity": "high", "category": "SECRETS"},
]

codex_findings = [
    {"path": "auth.py", "line": 42, "rule_id": "SQL-INJECT",
     "severity": "critical", "category": "SAST"},
    {"path": "db.py", "line": 15, "rule_id": "SQL-002",
     "severity": "high", "category": "SAST"},
]

report = calculator.compare_findings(argus_findings, codex_findings)

print(f"Match Rate: {report.simple_agreement_rate:.1%}")
print(f"Kappa: {report.cohens_kappa.kappa:.3f}")
print(f"Precision: {report.precision_recall.precision:.3f}")
print(f"Recall: {report.precision_recall.recall:.3f}")
```

### Example 2: Analyze by Severity

```python
report = calculator.compare_findings(argus, codex)

for sev_agreement in report.severity_agreements:
    print(f"{sev_agreement.severity.upper()}: "
          f"{sev_agreement.agreement_rate:.1%} agreement")

# Output:
# CRITICAL: 100.0% agreement
# HIGH: 75.0% agreement
# MEDIUM: 50.0% agreement
```

### Example 3: Statistical Significance

```python
report = calculator.compare_findings(large_dataset_1, large_dataset_2)

kappa = report.cohens_kappa
print(f"Kappa: {kappa.kappa:.3f}")
print(f"95% CI: [{kappa.confidence_interval_lower:.3f}, "
      f"{kappa.confidence_interval_upper:.3f}]")

if kappa.p_value < 0.05:
    print("Agreement is STATISTICALLY SIGNIFICANT")
else:
    print("Agreement could be by chance")
```

## Output Format

### JSON Report Structure

```json
{
  "timestamp": "2026-01-14T12:00:00.000000+00:00",
  "argus_finding_count": 10,
  "codex_finding_count": 12,
  "total_matches": 8,
  "total_unique_to_argus": 2,
  "total_unique_to_codex": 4,
  "simple_agreement_rate": 0.8,
  "cohens_kappa": {
    "kappa": 0.75,
    "std_error": 0.05,
    "confidence_interval_lower": 0.65,
    "confidence_interval_upper": 0.85,
    "p_value": 0.0001,
    "interpretation": "Substantial"
  },
  "precision_recall": {
    "precision": 0.8,
    "recall": 1.0,
    "f1_score": 0.889,
    "accuracy": 0.96,
    "specificity": 0.95,
    "false_positive_rate": 0.05,
    "false_negative_rate": 0.0
  },
  "confusion_matrix": {
    "true_positive": 8,
    "false_positive": 2,
    "false_negative": 0,
    "true_negative": 80
  },
  "severity_agreements": [
    {
      "severity": "critical",
      "argus_count": 3,
      "codex_count": 3,
      "both_agree": 3,
      "agreement_rate": 1.0,
      "kappa": 1.0
    }
  ],
  "category_agreements": [...],
  "severity_distribution": {
    "argus": {"critical": 3, "high": 5, "medium": 2},
    "codex": {"critical": 4, "high": 4, "medium": 4}
  },
  "category_distribution": {...}
}
```

## Visualization Integration

The module produces visualization-ready data:

### Severity Distribution (Bar Chart)
```python
distribution = report.severity_distribution
# Use for comparing severity distributions between tools
# Ideal for Matplotlib, Plotly, or Tableau
```

### Category Distribution (Pie/Bar Chart)
```python
categories = report.category_distribution
# Shows breakdown by finding type (SAST, SECRETS, DEPS, etc.)
```

### Agreement by Category (Stacked Bar)
```python
# Severity agreements
for sev in report.severity_agreements:
    print(f"{sev.severity}: {sev.agreement_rate:.0%}")

# Category agreements
for cat in report.category_agreements:
    print(f"{cat.category}: {cat.agreement_rate:.0%}")
```

## Performance Characteristics

- **Time Complexity**: O(n * m) for n Argus findings and m Codex findings
- **Space Complexity**: O(n + m)
- **Typical Performance**: <100ms for 100-1000 findings each

### Tested with
- 2 findings vs 2 findings: instant
- 50 findings vs 40 findings: ~1-2ms
- 1000 findings vs 1000 findings: ~50-100ms

## Error Handling

The module includes robust error handling:

```python
try:
    report = calculator.compare_findings(findings1, findings2)
except Exception as e:
    logger.error(f"Comparison failed: {e}")
    # Returns partial report with default values
```

- Missing fields default to standard values
- Invalid severities/categories are normalized to "UNKNOWN"
- Empty inputs return zero-initialized report
- All statistical calculations handle edge cases

## Testing

Comprehensive test suite with 36 tests covering:

- Cohen's Kappa interpretation
- Confusion matrix calculations
- Precision/Recall metrics
- Finding matching algorithm
- Agreement calculations
- Statistical tests
- File I/O operations
- Complete workflows

Run tests:
```bash
pytest scripts/test_metrics_calculator.py -v

# With coverage
pytest scripts/test_metrics_calculator.py -v --cov=scripts/metrics_calculator

# Coverage: 91% (352 statements)
```

## Integration Points

### With Orchestrator
```python
from metrics_calculator import MetricsCalculator

# In orchestrator workflow
calculator = MetricsCalculator()
report = calculator.compare_findings(
    orchestrator.argus_findings,
    orchestrator.codex_findings
)
```

### With Report Generator
```python
# Include metrics in security reports
metrics_data = report.to_dict()
report_generator.add_section("metrics", metrics_data)
```

### With Dashboard
```python
# Export for visualization dashboards
json_report = report.to_json()
dashboard_api.upload_metrics(json_report)
```

## Advanced Topics

### Custom Match Score Function
To adjust how findings are matched, modify `_calculate_match_score`:

```python
def _calculate_match_score(self, finding1: dict, finding2: dict) -> float:
    # Current weights: path(0.4), line(0.2), rule_id(0.2),
    #                  severity(0.1), category(0.1)
    # Customize based on your needs
    score = 0.0
    score += 0.5 if finding1.get("path") == finding2.get("path") else 0
    # ... custom logic
    return min(score, 1.0)
```

### Custom Contingency Table
For non-binary classification, extend contingency table logic in `_build_contingency_table`.

### Multi-Source Comparison
Extend for 3+ sources:
```python
def compare_three_sources(self, source1, source2, source3):
    report1 = self.compare_findings(source1, source2)
    report2 = self.compare_findings(source1, source3)
    # Aggregate results
```

## Dependencies

```
numpy>=1.21.0       # Arrays and math operations
scipy>=1.7.0        # Statistical tests (chi2_contingency, norm)
```

Both are included in the project's `requirements.txt`.

## Limitations

1. **Binary Classification**: Current implementation assumes binary presence/absence of findings
2. **Contingency Table Size**: 2x2 matrices for simplicity (could extend to multi-class)
3. **Finding Scope**: Assumes both sources are scanning the same codebase
4. **Rule ID Mapping**: Requires good rule ID alignment between tools
5. **Performance**: O(n*m) complexity may be slow for very large datasets (10K+ findings)

## Future Enhancements

1. **Fleiss' Kappa**: For 3+ raters
2. **Krippendorff's Alpha**: More flexible agreement measure
3. **Machine Learning**: Learn optimal match weights from training data
4. **Time Series**: Track agreement changes across commits/time
5. **Clustering**: Group related findings before comparison
6. **Visualization Export**: Direct Plotly/Matplotlib chart generation

## References

- Landis, J.R., Koch, G.G. (1977). "The measurement of observer agreement for categorical data." Biometrics 33:159-74.
- Cohen, J. (1960). "A coefficient of agreement for nominal scales." Educational and Psychological Measurement 20:37-46.
- McHugh, M.L. (2012). "Interrater reliability: the kappa statistic." Biochemia Medica 22(3):276-282.

## Support

For issues or questions:
1. Check `/examples/metrics_calculator_example.py` for usage patterns
2. Review test suite in `/scripts/test_metrics_calculator.py`
3. Check docstrings in `/scripts/metrics_calculator.py`
4. Open an issue with sample data for debugging
