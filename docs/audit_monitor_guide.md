# Audit Monitor - Comprehensive Dual-Audit Tracking and Analysis

## Overview

The **Audit Monitor** (`audit_monitor.py`) is a sophisticated monitoring system that tracks and analyzes dual-audit results from Argus and Codex validation. It provides historical tracking, trend analysis, criteria drift detection, and intelligent alerting to maintain high quality assurance standards.

## Architecture

### Core Components

```
AuditMonitor
├── Database Management
│   ├── Schema initialization
│   ├── Persistent storage
│   └── Transaction handling
├── Data Ingestion
│   ├── Audit run storage
│   ├── Findings comparison
│   └── Validation
├── Analysis Engine
│   ├── Drift detection
│   ├── Outlier identification
│   ├── Trend analysis
│   └── Statistical analysis
├── Alert System
│   ├── Agreement monitoring
│   ├── Outlier alerts
│   ├── Drift notifications
│   └── Acknowledgment tracking
└── Metrics Generator
    ├── Dashboard data
    ├── Historical trends
    ├── Health scoring
    └── Report generation
```

### Database Schema

#### 1. `audit_runs` Table
Stores high-level summary of each dual-audit execution.

```sql
CREATE TABLE audit_runs (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    repo TEXT NOT NULL,
    project_type TEXT,
    argus_findings_count INTEGER,
    codex_findings_count INTEGER,
    agreed_findings_count INTEGER,
    argus_only_count INTEGER,
    codex_only_count INTEGER,
    agreement_rate REAL NOT NULL,
    average_score_difference REAL,
    severity_distribution TEXT,      -- JSON
    metadata TEXT,                   -- JSON
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(repo, timestamp)
)
```

**Key Metrics:**
- `agreement_rate`: Percentage of findings both systems agree on
- `average_score_difference`: Mean absolute difference in severity scores
- `severity_distribution`: Breakdown by severity levels (critical, high, medium, low)

#### 2. `findings_comparison` Table
Detailed comparison of individual findings between Argus and Codex.

```sql
CREATE TABLE findings_comparison (
    id TEXT PRIMARY KEY,
    audit_run_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    argus_score REAL NOT NULL,      -- 1.0-5.0 scale
    codex_score REAL NOT NULL,         -- 1.0-5.0 scale
    score_difference REAL NOT NULL,    -- |argus - codex|
    agreed INTEGER NOT NULL,           -- 0 or 1
    argus_verdict TEXT,             -- definitely_valid, likely_valid, etc.
    codex_verdict TEXT,
    severity TEXT,                     -- critical, high, medium, low
    category TEXT,                     -- SAST, DEPS, SECRETS, IAC, etc.
    metadata TEXT,                     -- JSON with additional context
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (audit_run_id) REFERENCES audit_runs(id),
    UNIQUE(audit_run_id, finding_id)
)
```

#### 3. `drift_events` Table
Tracks detected changes in evaluation criteria over time.

```sql
CREATE TABLE drift_events (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    audit_run_id TEXT NOT NULL,
    metric_name TEXT NOT NULL,          -- e.g., "category_emphasis_SAST"
    metric_type TEXT NOT NULL,          -- category_emphasis, severity_weighting, threshold_change
    old_value REAL,                     -- Previous value
    new_value REAL,                     -- Current value
    change_magnitude REAL NOT NULL,     -- |new - old|
    statistical_significance REAL NOT NULL,  -- 0.0-1.0
    confidence REAL NOT NULL,           -- 0.0-1.0 (how confident in this drift)
    description TEXT,                   -- Human-readable explanation
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (audit_run_id) REFERENCES audit_runs(id)
)
```

#### 4. `alerts` Table
Generated alerts for anomalies and threshold violations.

```sql
CREATE TABLE alerts (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    audit_run_id TEXT NOT NULL,
    alert_type TEXT NOT NULL,      -- agreement_drop, drift_detected, outlier_finding, quality_degradation
    severity TEXT NOT NULL,        -- info, warning, critical
    message TEXT NOT NULL,         -- Human-readable alert message
    metric_name TEXT,              -- Which metric triggered the alert
    metric_value REAL,             -- Current value of metric
    threshold REAL,                -- Threshold that was crossed
    metadata TEXT,                 -- JSON with additional context
    acknowledged INTEGER DEFAULT 0, -- 0 or 1
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (audit_run_id) REFERENCES audit_runs(id)
)
```

## Usage Guide

### Initialization

```python
from audit_monitor import AuditMonitor, AuditRun, FindingComparison

# Initialize monitor with custom settings
monitor = AuditMonitor(
    db_path=".argus/audit_monitor.db",
    agreement_threshold=0.75,    # Alert if agreement < 75%
    drift_sensitivity=0.15,      # Detect drift if change > 15%
    enable_cleanup=True           # Auto-cleanup old records
)
```

### Storing Audit Results

```python
from datetime import datetime, timezone

# Create audit run summary
audit_run = AuditRun(
    id="audit-20260114-abc123",
    timestamp=datetime.now(timezone.utc).isoformat(),
    repo="my-repo",
    project_type="backend-api",
    argus_findings_count=45,
    codex_findings_count=48,
    agreed_findings_count=42,
    argus_only_count=3,
    codex_only_count=6,
    agreement_rate=0.88,
    average_score_difference=0.24,
    severity_distribution={
        "critical": 5,
        "high": 15,
        "medium": 20,
        "low": 8
    },
    metadata={
        "branch": "main",
        "commit": "abc123def456",
        "scan_duration_seconds": 120
    }
)

# Create detailed findings comparisons
findings = [
    FindingComparison(
        id="finding-001",
        audit_run_id=audit_run.id,
        finding_id="finding-001",
        argus_score=4.8,
        codex_score=4.5,
        score_difference=0.3,
        agreed=True,
        argus_verdict="definitely_valid",
        codex_verdict="likely_valid",
        severity="critical",
        category="SAST",
        metadata={"rule": "sql-injection", "cwe": "CWE-89"}
    ),
    # ... more findings
]

# Store in database
success, error = monitor.store_audit_run(audit_run, findings)
if success:
    print("Audit run stored and analyzed")
else:
    print(f"Failed: {error}")
```

### Querying Historical Data

```python
# Get all audit runs for a repository (last 30 days)
history = monitor.get_audit_history(
    repo="my-repo",
    days=30,
    limit=100
)

for run in history:
    print(f"{run.timestamp}: {run.agreement_rate:.1%} agreement")

# Get agreement rate trend for charting
trend = monitor.get_agreement_trend(repo="my-repo", days=30)
# Output: [
#     {"timestamp": "2026-01-10T...", "agreement_rate": 0.85},
#     {"timestamp": "2026-01-11T...", "agreement_rate": 0.87},
#     ...
# ]
```

### Monitoring Drift Detection

The system automatically detects three types of criteria drift:

#### 1. Category Distribution Drift
Monitors if evaluation emphasis is shifting across finding categories (SAST, DEPS, SECRETS, IAC).

```python
# Example: If SAST findings were 75% and now 50% (>15% change),
# a drift event is recorded
drift_events = monitor.get_recent_drift_events(days=7)

for event in drift_events:
    if "category" in event.metric_name:
        print(f"Category shift: {event.metric_name}")
        print(f"  {event.old_value:.1%} -> {event.new_value:.1%}")
        print(f"  Confidence: {event.confidence:.1%}")
```

#### 2. Severity Weighting Drift
Detects when agreement rates by severity level change significantly.

```python
# Example: If high-severity findings had 95% agreement
# and now have 75% agreement (>15% change)
for event in drift_events:
    if "severity_weighting" in event.metric_name:
        print(f"Severity agreement shift: {event.description}")
```

#### 3. Score Distribution Drift
Uses Kolmogorov-Smirnov test to detect shifts in overall score distributions.

```python
# Example: If average score difference was 0.15
# and now is 0.35 (>15% change)
for event in drift_events:
    if "score_distribution" in event.metric_name:
        print(f"Score distribution shift: {event.description}")
```

### Alert Management

```python
# Get active unacknowledged alerts
alerts = monitor.get_active_alerts(severity="warning", limit=50)

for alert in alerts:
    print(f"[{alert.severity}] {alert.alert_type}")
    print(f"  {alert.message}")
    print(f"  Metric: {alert.metric_name} = {alert.metric_value}")

    # Acknowledge alert after reviewing
    monitor.acknowledge_alert(alert.id)
```

### Dashboard Metrics Generation

```python
# Generate comprehensive metrics for visualization
metrics = monitor.generate_dashboard_metrics(
    repo="my-repo",
    days=30
)

# Output includes:
# - Current agreement rate and trend
# - Historical agreement rates
# - Recent drift events
# - Active alerts by type
# - Overall health score (0-100)

print(f"Current Agreement: {metrics['summary']['current_agreement_rate']:.1%}")
print(f"Health Score: {metrics['health_score']:.0f}/100")
print(f"Active Alerts: {metrics['alerts']['active_count']}")
print(f"Drift Events (High Confidence): {metrics['drift']['high_confidence_events']}")
```

## Detection Algorithms

### Drift Detection

All drift detection algorithms are statistical and use configurable sensitivity thresholds.

#### Category Distribution Analysis
```
1. Calculate category percentages for current and historical audits
2. For each category:
   - Compare current % to historical average %
   - If |current - historical| > drift_sensitivity (default 15%):
     - Calculate statistical significance (stdev-based)
     - Record drift event with confidence score
```

#### Severity Agreement Correlation
```
1. Group findings by severity level
2. Calculate agreement rate per severity
3. For each severity:
   - Compare current agreement % to historical average
   - If |current - historical| > drift_sensitivity:
     - Record as severity weighting drift
     - Flag if critical/high severity affected
```

#### Score Distribution (Kolmogorov-Smirnov)
```
1. Extract all score differences (argus_score - codex_score) for current run
2. Extract all score differences from historical runs
3. Calculate empirical CDFs for both distributions
4. K-S statistic = max|CDF_current - CDF_historical|
5. If K-S > drift_sensitivity:
   - Record as score distribution drift
   - Indicates systematic evaluation changes
```

### Outlier Detection (IQR Method)

```
1. Get all score differences from audit run
2. Calculate Q1 (25th percentile) and Q3 (75th percentile)
3. Calculate IQR = Q3 - Q1
4. Lower bound = Q1 - 1.5*IQR
5. Upper bound = Q3 + 1.5*IQR
6. Finding is outlier if score_difference exceeds bounds
```

### Health Score Calculation

```
health_score = (agreement_component) + (drift_component) + (alert_component)

where:
  agreement_component = agreement_rate * 40.0      (0-40 points)
  drift_component = max(0, 30.0 - drift_count*2.0) (0-30 points)
  alert_component = max(0, 30.0 - alert_count*0.5) (0-30 points)

final = min(100.0, max(0.0, total))
```

## Configuration

### Initialization Parameters

```python
monitor = AuditMonitor(
    db_path=".argus/audit_monitor.db",    # Database location
    agreement_threshold=0.75,                  # Alert threshold (0-1)
    drift_sensitivity=0.15,                    # Drift detection sensitivity (0-1, lower = more sensitive)
    enable_cleanup=True                        # Auto-cleanup old records
)
```

### Alert Thresholds

Alert types and their triggers:

| Alert Type | Trigger | Threshold |
|-----------|---------|-----------|
| `agreement_drop` | Agreement rate falls below threshold | `agreement_threshold` |
| `outlier_finding` | Finding score difference exceeds IQR bounds | Statistical (IQR*1.5) |
| `drift_detected` | Evaluation criteria change detected | `drift_sensitivity` |
| `quality_degradation` | Multiple indicators degrade together | Composite |

## Data Management

### Automatic Cleanup

```python
# Cleanup records older than 90 days
deleted_count = monitor.cleanup_old_data(keep_days=90)
print(f"Deleted {deleted_count} old audit runs")

# Recommended: Run monthly or quarterly
```

### Database Performance

The system includes indexes on frequently queried columns:
- `audit_runs(timestamp)` - For historical queries
- `audit_runs(repo)` - For repo-specific analysis
- `findings_comparison(audit_run_id)` - For finding lookups
- `drift_events(audit_run_id)` - For drift event queries
- `alerts(timestamp)` - For alert retrieval

## Integration Examples

### With Dual-Audit System

```python
from dual_audit import DualAuditOrchestrator
from audit_monitor import AuditMonitor, AuditRun, FindingComparison

# Run dual audit
orchestrator = DualAuditOrchestrator(target_repo, project_type)
argus_results = orchestrator.run_argus_audit()
codex_results = orchestrator.run_codex_validation(argus_results)

# Calculate agreement metrics
findings_comparisons = []
for finding in codex_results["compared_findings"]:
    comparison = FindingComparison(
        id=f"{finding['id']}-comparison",
        audit_run_id=run_id,
        finding_id=finding['id'],
        argus_score=finding['argus_score'],
        codex_score=finding['codex_score'],
        score_difference=abs(finding['argus_score'] - finding['codex_score']),
        agreed=finding['agreed'],
        argus_verdict=finding['argus_verdict'],
        codex_verdict=finding['codex_verdict'],
        severity=finding['severity'],
        category=finding['category'],
        metadata={"rule": finding.get('rule_id')}
    )
    findings_comparisons.append(comparison)

# Store in monitoring system
monitor = AuditMonitor()
success, error = monitor.store_audit_run(audit_run, findings_comparisons)
```

### Dashboard Integration

```python
# Generate metrics for web dashboard
monitor = AuditMonitor()
metrics = monitor.generate_dashboard_metrics(repo="my-repo", days=30)

# Serialize for JSON API
import json
dashboard_json = json.dumps(metrics, indent=2)

# Frontend can then visualize:
# - Agreement rate trend chart
# - Severity distribution pie chart
# - Recent alerts list
# - Health score gauge
# - Drift events timeline
```

## Best Practices

1. **Store Results Immediately**: Call `store_audit_run()` right after audit completes
2. **Review Alerts Daily**: Check `get_active_alerts()` to catch issues early
3. **Monitor Drift Events**: Investigate high-confidence drift events (>80%)
4. **Track Health Score**: Keep it above 70 for optimal performance
5. **Cleanup Old Data**: Run `cleanup_old_data()` monthly to maintain database performance
6. **Set Appropriate Thresholds**: Adjust `agreement_threshold` and `drift_sensitivity` based on your team's standards

## Example Reports

### Weekly Summary Report

```python
monitor = AuditMonitor()
metrics = monitor.generate_dashboard_metrics(days=7)

report = f"""
WEEKLY AUDIT SUMMARY
====================

Agreement: {metrics['summary']['current_agreement_rate']:.1%}
Trend: {metrics['summary']['agreement_trend']:+.2%}
Health Score: {metrics['health_score']:.0f}/100

Recent Runs: {metrics['trends']['audit_count']}
Active Alerts: {metrics['alerts']['active_count']}
High-Confidence Drift Events: {metrics['drift']['high_confidence_events']}

Status: {'HEALTHY' if metrics['health_score'] > 70 else 'NEEDS ATTENTION'}
"""
print(report)
```

### Drift Analysis Report

```python
drift_events = monitor.get_recent_drift_events(days=7, limit=50)

high_confidence = [e for e in drift_events if e.confidence > 0.8]
print(f"High-Confidence Drift Events: {len(high_confidence)}")

for event in high_confidence:
    print(f"\n{event.metric_name}:")
    print(f"  Type: {event.metric_type}")
    print(f"  Change: {event.old_value:.3f} -> {event.new_value:.3f}")
    print(f"  Magnitude: {event.change_magnitude:.1%}")
    print(f"  Confidence: {event.confidence:.1%}")
    print(f"  Details: {event.description}")
```

## Testing

Comprehensive test suite with 21+ test cases:

```bash
# Run all tests
pytest tests/unit/test_audit_monitor.py -v

# Run specific test class
pytest tests/unit/test_audit_monitor.py::TestDriftDetection -v

# Run with coverage
pytest tests/unit/test_audit_monitor.py --cov=scripts/audit_monitor
```

Test coverage includes:
- Database initialization and schema
- Audit run storage and retrieval
- Historical query operations
- Drift detection algorithms
- Outlier identification
- Alert generation and acknowledgment
- Metrics generation
- Data cleanup operations

## Troubleshooting

### Issue: Drift events not detected
**Solution**: Check `drift_sensitivity` setting. Lower values are more sensitive. Default 0.15 (15% change).

### Issue: Too many alerts
**Solution**: Increase `agreement_threshold` or adjust alert severity levels in configuration.

### Issue: Database growth
**Solution**: Run `cleanup_old_data(keep_days=90)` periodically to remove old records.

### Issue: Performance degradation
**Solution**: Ensure indexes are present via `_initialize_db()` and run VACUUM on database periodically.

## Future Enhancements

- Machine learning-based anomaly detection
- Integration with external alerting (Slack, PagerDuty)
- Real-time dashboard WebSocket updates
- Comparison with external security scan results
- Predictive agreement rate forecasting
- Custom rule engine for alert generation

## References

- Dual-Audit System: See `dual_audit.py`
- Finding Normalization: See `normalizer/base.py`
- Risk Scoring: See `risk_scorer.py`
