# Audit Monitor - Quick Start Guide

## 5-Minute Setup

### Installation
```bash
# No additional dependencies required - uses standard library + sqlite3
# Just copy the file to your scripts directory (already done)

ls -la scripts/audit_monitor.py
# -rwxr-xr-x audit_monitor.py
```

### Basic Usage
```python
from scripts.audit_monitor import AuditMonitor, AuditRun, FindingComparison
from datetime import datetime, timezone

# 1. Initialize monitor
monitor = AuditMonitor(db_path=".argus/audit_monitor.db")

# 2. Create audit run
audit_run = AuditRun(
    id="audit-001",
    timestamp=datetime.now(timezone.utc).isoformat(),
    repo="my-repo",
    project_type="backend-api",
    argus_findings_count=50,
    codex_findings_count=52,
    agreed_findings_count=45,
    argus_only_count=5,
    codex_only_count=7,
    agreement_rate=0.88,
    average_score_difference=0.20,
    severity_distribution={"critical": 5, "high": 20, "medium": 20, "low": 5},
    metadata={"branch": "main"}
)

# 3. Create findings comparisons
findings = [
    FindingComparison(
        id="finding-1",
        audit_run_id=audit_run.id,
        finding_id="finding-1",
        argus_score=4.5,
        codex_score=4.2,
        score_difference=0.3,
        agreed=True,
        argus_verdict="likely_valid",
        codex_verdict="likely_valid",
        severity="high",
        category="SAST",
        metadata={}
    )
]

# 4. Store results
success, error = monitor.store_audit_run(audit_run, findings)
if success:
    print("✓ Audit stored successfully")
else:
    print(f"✗ Error: {error}")

# 5. Get metrics
metrics = monitor.generate_dashboard_metrics()
print(f"Current agreement: {metrics['summary']['current_agreement_rate']:.1%}")
print(f"Health score: {metrics['health_score']:.0f}/100")

# 6. Check alerts
alerts = monitor.get_active_alerts()
print(f"Active alerts: {len(alerts)}")
for alert in alerts:
    print(f"  - [{alert.severity}] {alert.message}")
```

## Common Tasks

### Store Audit Results from Dual-Audit
```python
from audit_monitor import AuditMonitor, AuditRun, FindingComparison

monitor = AuditMonitor()

# After running dual_audit.py, you have:
# - argus_results: Dict with findings from Argus
# - codex_results: Dict with findings from Codex

# Create comparison function
def compare_findings(argus_findings, codex_findings):
    # Match findings between systems
    agreed = sum(1 for f in argus_findings
                 if any(c['id'] == f['id'] for c in codex_findings))
    return {
        'argus': len(argus_findings),
        'codex': len(codex_findings),
        'agreed': agreed,
        'agreement_rate': agreed / max(len(argus_findings), len(codex_findings))
    }

comparison = compare_findings(argus_findings, codex_findings)

audit_run = AuditRun(
    id=f"audit-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
    timestamp=datetime.now(timezone.utc).isoformat(),
    repo="my-repo",
    project_type="backend-api",
    argus_findings_count=comparison['argus'],
    codex_findings_count=comparison['codex'],
    agreed_findings_count=comparison['agreed'],
    argus_only_count=comparison['argus'] - comparison['agreed'],
    codex_only_count=comparison['codex'] - comparison['agreed'],
    agreement_rate=comparison['agreement_rate'],
    average_score_difference=0.25,
    severity_distribution={...},
    metadata={}
)

monitor.store_audit_run(audit_run, [])
```

### Monitor Agreement Trends
```python
monitor = AuditMonitor()

# Get trend for last 30 days
trend = monitor.get_agreement_trend(repo="my-repo", days=30)

# Plot or analyze
for point in trend:
    print(f"{point['timestamp']}: {point['agreement_rate']:.1%}")

# Calculate trend
rates = [p['agreement_rate'] for p in trend]
if len(rates) > 1:
    trend_direction = "↑ improving" if rates[-1] > rates[0] else "↓ degrading"
    print(f"Trend: {trend_direction} ({rates[0]:.1%} → {rates[-1]:.1%})")
```

### Detect and Handle Drift
```python
monitor = AuditMonitor()

# Get recent drift events
drift_events = monitor.get_recent_drift_events(days=7)

# Filter high-confidence drifts
important_drifts = [e for e in drift_events if e.confidence > 0.8]

for drift in important_drifts:
    print(f"⚠️  {drift.metric_name}")
    print(f"   Change: {drift.old_value:.3f} → {drift.new_value:.3f}")
    print(f"   Confidence: {drift.confidence:.1%}")
    print(f"   Details: {drift.description}")
```

### Check and Acknowledge Alerts
```python
monitor = AuditMonitor()

# Get active alerts
alerts = monitor.get_active_alerts()

print(f"📢 {len(alerts)} active alerts:\n")

for alert in alerts:
    status = "⚠️ " if alert.severity == "warning" else "ℹ️ "
    print(f"{status} [{alert.alert_type}] {alert.message}")

    if alert.alert_type == "outlier_finding":
        # Investigate outlier
        print(f"   Finding: {alert.metric_name} = {alert.metric_value:.2f}")

    # Acknowledge after review
    monitor.acknowledge_alert(alert.id)
    print("   ✓ Acknowledged\n")
```

### Generate Dashboard Data
```python
import json
monitor = AuditMonitor()

# Get comprehensive metrics
metrics = monitor.generate_dashboard_metrics(repo="my-repo", days=30)

# Display summary
summary = metrics['summary']
print(f"""
╔════════════════════════════════════════╗
║   Dual-Audit Dashboard Summary         ║
╠════════════════════════════════════════╣
║ Current Agreement:  {summary['current_agreement_rate']:>6.1%}         ║
║ Average Agreement:  {summary['average_agreement_rate']:>6.1%}         ║
║ Trend:              {summary['agreement_trend']:>+6.1%}         ║
║ Health Score:       {metrics['health_score']:>6.0f}/100      ║
║ Active Alerts:      {metrics['alerts']['active_count']:>6d}          ║
║ Drift Events:       {metrics['drift']['total_events']:>6d}          ║
╚════════════════════════════════════════╝
""")

# Export for charting
chart_data = {
    'agreement_rates': metrics['trends']['agreement_rates'],
    'timestamps': [r['timestamp'] for r in monitor.get_agreement_trend(days=30)]
}
print(json.dumps(chart_data, indent=2))
```

## Testing

### Run Test Suite
```bash
# All tests
pytest tests/unit/test_audit_monitor.py -v

# Specific test
pytest tests/unit/test_audit_monitor.py::TestDriftDetection -v

# With coverage
pytest tests/unit/test_audit_monitor.py --cov=scripts/audit_monitor
```

### Manual Testing
```python
# Test basic functionality
from audit_monitor import AuditMonitor

monitor = AuditMonitor(db_path=".test-audit.db")
print("✓ Database initialized")

# Test ID generation
id1 = AuditMonitor._generate_id("test")
print(f"✓ Generated ID: {id1}")

# Test health score
score = monitor._calculate_health_score(0.85, 2, 5)
print(f"✓ Health score: {score:.0f}/100")

print("\nAll basic tests passed!")
```

## Configuration Tips

### For Strict Auditing (Low Tolerance for Drift)
```python
monitor = AuditMonitor(
    agreement_threshold=0.85,    # Require 85%+ agreement
    drift_sensitivity=0.10       # Alert on 10%+ changes
)
```

### For Lenient Auditing (High Tolerance)
```python
monitor = AuditMonitor(
    agreement_threshold=0.65,    # Require 65%+ agreement
    drift_sensitivity=0.25       # Alert on 25%+ changes
)
```

### Standard Configuration (Recommended)
```python
monitor = AuditMonitor(
    agreement_threshold=0.75,    # Industry standard
    drift_sensitivity=0.15       # Balanced sensitivity
)
```

## Troubleshooting

### Q: No drift events detected
**A**: Check `drift_sensitivity`. Default 0.15 = 15% threshold. Lower for more sensitivity:
```python
monitor = AuditMonitor(drift_sensitivity=0.10)
```

### Q: Too many alerts
**A**: Increase `agreement_threshold` or check alert filtering:
```python
# Get only warning+ severity
alerts = monitor.get_active_alerts(severity="warning")
```

### Q: Database growing large
**A**: Run cleanup to remove old records:
```python
deleted = monitor.cleanup_old_data(keep_days=90)
print(f"Deleted {deleted} old audit runs")
```

### Q: Slow queries
**A**: Ensure indexes exist (created automatically) and consider cleanup:
```python
# Check database size
import os
size_mb = os.path.getsize(".argus/audit_monitor.db") / (1024*1024)
print(f"Database: {size_mb:.1f} MB")
```

## Next Steps

1. **Read Full Documentation**: `docs/audit_monitor_guide.md`
2. **Review Integration Example**: `scripts/audit_monitor_integration_example.py`
3. **Setup Monitoring Dashboard**: Use `generate_dashboard_metrics()` output
4. **Configure Alerts**: Adjust `agreement_threshold` and `drift_sensitivity`
5. **Schedule Cleanup**: Run `cleanup_old_data()` monthly
6. **Monitor Trends**: Review `get_recent_drift_events()` weekly
7. **Test Integration**: Run test suite: `pytest tests/unit/test_audit_monitor.py`

## Key Commands Cheat Sheet

```python
from audit_monitor import AuditMonitor

monitor = AuditMonitor()

# Query
audit = monitor.get_audit_run(id)
history = monitor.get_audit_history(repo="r", days=30)
trend = monitor.get_agreement_trend(days=30)
drift = monitor.get_recent_drift_events(days=7)
alerts = monitor.get_active_alerts()

# Store
monitor.store_audit_run(audit_run, findings)

# Manage
monitor.acknowledge_alert(alert_id)
monitor.cleanup_old_data(keep_days=90)

# Metrics
metrics = monitor.generate_dashboard_metrics()
health = monitor._calculate_health_score(0.85, 2, 5)
```

## Support Resources

- **Full Guide**: `/docs/audit_monitor_guide.md`
- **Integration Example**: `/scripts/audit_monitor_integration_example.py`
- **Test Examples**: `/tests/unit/test_audit_monitor.py`
- **Source Code**: `/scripts/audit_monitor.py`

---

**Ready to go!** Start with the basic usage example and explore the features.
