#!/usr/bin/env python3
"""
Audit Monitor Integration Example
Demonstrates how to integrate the Audit Monitor with the Dual-Audit system

This example shows:
1. Running a dual audit
2. Capturing and comparing results
3. Storing results in monitoring database
4. Analyzing trends and detecting drift
5. Generating dashboard metrics
6. Managing alerts
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def integrate_audit_monitor_with_dual_audit(
    argus_results: Dict[str, Any],
    codex_results: Dict[str, Any],
    repo_name: str,
    project_type: str,
) -> None:
    """
    Integrate Audit Monitor with Dual-Audit results

    Args:
        argus_results: Results from Argus audit
        codex_results: Results from Codex validation
        repo_name: Repository name
        project_type: Project type (backend-api, frontend, etc.)
    """
    import sys
    sys.path.insert(0, str(Path(__file__).parent))

    from audit_monitor import (
        AuditMonitor,
        AuditRun,
        FindingComparison
    )

    # Initialize monitor
    monitor = AuditMonitor(
        db_path=".argus/audit_monitor.db",
        agreement_threshold=0.75,
        drift_sensitivity=0.15
    )

    # Extract findings from results
    argus_findings = argus_results.get("findings", [])
    codex_findings = codex_results.get("findings", [])

    logger.info(f"Argus findings: {len(argus_findings)}")
    logger.info(f"Codex findings: {len(codex_findings)}")

    # Create mapping of findings for comparison
    findings_by_id: Dict[str, Any] = {}

    # Add Argus findings
    for finding in argus_findings:
        finding_id = finding.get("id", finding.get("rule_id", ""))
        if not findings_by_id.get(finding_id):
            findings_by_id[finding_id] = {
                "id": finding_id,
                "argus_finding": finding,
                "codex_finding": None,
                "path": finding.get("path", ""),
                "category": finding.get("category", "UNKNOWN"),
                "severity": finding.get("severity", "medium")
            }
        else:
            findings_by_id[finding_id]["argus_finding"] = finding

    # Add Codex findings and match with Argus
    for finding in codex_findings:
        finding_id = finding.get("id", finding.get("rule_id", ""))
        if not findings_by_id.get(finding_id):
            findings_by_id[finding_id] = {
                "id": finding_id,
                "argus_finding": None,
                "codex_finding": finding,
                "path": finding.get("path", ""),
                "category": finding.get("category", "UNKNOWN"),
                "severity": finding.get("severity", "medium")
            }
        else:
            findings_by_id[finding_id]["codex_finding"] = finding

    # Calculate agreement metrics
    agreed_findings = 0
    argus_only = 0
    codex_only = 0
    total_score_diff = 0.0
    score_diff_count = 0

    severity_distribution = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0
    }

    findings_comparisons: List[FindingComparison] = []

    for finding_id, comparison_data in findings_by_id.items():
        argus_finding = comparison_data["argus_finding"]
        codex_finding = comparison_data["codex_finding"]
        severity = comparison_data["severity"]

        # Count severity distribution
        severity_distribution[severity] = severity_distribution.get(severity, 0) + 1

        if argus_finding and codex_finding:
            # Both systems found it - check if they agree on severity/verdict
            argus_score = _score_finding(argus_finding)
            codex_score = _score_finding(codex_finding)
            score_diff = abs(argus_score - codex_score)

            # They agree if scores are within 1 point (0.5 would be strict, 1.0 is moderate)
            agreed = score_diff <= 1.0

            if agreed:
                agreed_findings += 1

            findings_comparisons.append(
                FindingComparison(
                    id=AuditMonitor._generate_id("finding"),
                    audit_run_id="",  # Will be set after audit_run created
                    finding_id=finding_id,
                    argus_score=argus_score,
                    codex_score=codex_score,
                    score_difference=score_diff,
                    agreed=agreed,
                    argus_verdict=_get_verdict(argus_score),
                    codex_verdict=_get_verdict(codex_score),
                    severity=severity,
                    category=comparison_data["category"],
                    metadata={
                        "path": comparison_data["path"],
                        "argus_rule": argus_finding.get("rule_id", ""),
                        "codex_rule": codex_finding.get("rule_id", "")
                    }
                )
            )

            total_score_diff += score_diff
            score_diff_count += 1

        elif argus_finding:
            argus_only += 1
            argus_score = _score_finding(argus_finding)

            findings_comparisons.append(
                FindingComparison(
                    id=AuditMonitor._generate_id("finding"),
                    audit_run_id="",
                    finding_id=finding_id,
                    argus_score=argus_score,
                    codex_score=0.0,
                    score_difference=argus_score,
                    agreed=False,
                    argus_verdict=_get_verdict(argus_score),
                    codex_verdict="not_found",
                    severity=severity,
                    category=comparison_data["category"],
                    metadata={
                        "path": comparison_data["path"],
                        "argus_rule": argus_finding.get("rule_id", ""),
                        "type": "argus_only"
                    }
                )
            )

        elif codex_finding:
            codex_only += 1
            codex_score = _score_finding(codex_finding)

            findings_comparisons.append(
                FindingComparison(
                    id=AuditMonitor._generate_id("finding"),
                    audit_run_id="",
                    finding_id=finding_id,
                    argus_score=0.0,
                    codex_score=codex_score,
                    score_difference=codex_score,
                    agreed=False,
                    argus_verdict="not_found",
                    codex_verdict=_get_verdict(codex_score),
                    severity=severity,
                    category=comparison_data["category"],
                    metadata={
                        "path": comparison_data["path"],
                        "codex_rule": codex_finding.get("rule_id", ""),
                        "type": "codex_only"
                    }
                )
            )

    # Calculate final metrics
    total_findings = len(findings_by_id)
    if total_findings > 0:
        agreement_rate = agreed_findings / total_findings
    else:
        agreement_rate = 1.0

    avg_score_diff = (
        total_score_diff / score_diff_count if score_diff_count > 0 else 0.0
    )

    # Create audit run
    audit_run = AuditRun(
        id=AuditMonitor._generate_id("audit"),
        timestamp=datetime.now(timezone.utc).isoformat(),
        repo=repo_name,
        project_type=project_type,
        argus_findings_count=len(argus_findings),
        codex_findings_count=len(codex_findings),
        agreed_findings_count=agreed_findings,
        argus_only_count=argus_only,
        codex_only_count=codex_only,
        agreement_rate=agreement_rate,
        average_score_difference=avg_score_diff,
        severity_distribution=severity_distribution,
        metadata={
            "integration_version": "1.0",
            "analyzed_at": datetime.now(timezone.utc).isoformat(),
            "total_findings_compared": total_findings
        }
    )

    # Update finding comparison audit_run_id
    for finding in findings_comparisons:
        finding.audit_run_id = audit_run.id

    # Store in monitoring system
    logger.info(f"Storing audit run: {audit_run.id}")
    logger.info(f"  Agreement rate: {agreement_rate:.1%}")
    logger.info(f"  Agreed findings: {agreed_findings}/{total_findings}")

    success, error = monitor.store_audit_run(audit_run, findings_comparisons)

    if success:
        logger.info("Audit run stored successfully")
        return audit_run.id
    else:
        logger.error(f"Failed to store audit run: {error}")
        return None


def analyze_audit_trends(
    repo_name: str,
    days: int = 30
) -> Dict[str, Any]:
    """
    Analyze audit trends for a repository

    Args:
        repo_name: Repository name
        days: Number of days to analyze

    Returns:
        Analysis report
    """
    import sys
    sys.path.insert(0, str(Path(__file__).parent))

    from audit_monitor import AuditMonitor

    monitor = AuditMonitor()

    # Get historical data
    history = monitor.get_audit_history(repo=repo_name, days=days)
    if not history:
        return {"status": "no_data"}

    # Calculate trends
    agreement_rates = [r.agreement_rate for r in history]
    score_diffs = [
        r.average_score_difference for r in history if r.average_score_difference
    ]

    import statistics
    avg_agreement = statistics.mean(agreement_rates)
    avg_score_diff = statistics.mean(score_diffs) if score_diffs else 0.0

    # Detect trend direction
    if len(agreement_rates) > 1:
        trend = agreement_rates[0] - agreement_rates[-1]
    else:
        trend = 0.0

    # Get active alerts
    alerts = monitor.get_active_alerts()
    alert_types = {}
    for alert in alerts:
        alert_types[alert.alert_type] = alert_types.get(alert.alert_type, 0) + 1

    # Get drift events
    drift_events = monitor.get_recent_drift_events(days=days)
    high_confidence_drift = [e for e in drift_events if e.confidence > 0.8]

    return {
        "status": "ok",
        "repository": repo_name,
        "period_days": days,
        "audit_count": len(history),
        "agreement": {
            "current": agreement_rates[0],
            "average": avg_agreement,
            "trend": trend,
            "history": agreement_rates
        },
        "score_difference": {
            "average": avg_score_diff,
            "history": score_diffs
        },
        "alerts": {
            "active_count": len(alerts),
            "by_type": alert_types
        },
        "drift": {
            "total_events": len(drift_events),
            "high_confidence": len(high_confidence_drift)
        }
    }


def generate_dashboard_report(
    repo_name: str = None,
    days: int = 30
) -> Dict[str, Any]:
    """
    Generate comprehensive dashboard report

    Args:
        repo_name: Repository to report on (None = all)
        days: Days to include

    Returns:
        Dashboard metrics
    """
    import sys
    sys.path.insert(0, str(Path(__file__).parent))

    from audit_monitor import AuditMonitor

    monitor = AuditMonitor()
    return monitor.generate_dashboard_metrics(repo=repo_name, days=days)


def handle_alerts(
    auto_acknowledge: bool = False
) -> Dict[str, Any]:
    """
    Review and handle active alerts

    Args:
        auto_acknowledge: Automatically acknowledge low-severity alerts

    Returns:
        Alert summary
    """
    import sys
    sys.path.insert(0, str(Path(__file__).parent))

    from audit_monitor import AuditMonitor

    monitor = AuditMonitor()
    alerts = monitor.get_active_alerts()

    alert_summary = {
        "total": len(alerts),
        "by_severity": {},
        "processed": 0
    }

    for alert in alerts:
        # Count by severity
        severity = alert.severity
        alert_summary["by_severity"][severity] = (
            alert_summary["by_severity"].get(severity, 0) + 1
        )

        logger.warning(f"[{alert.severity}] {alert.alert_type}: {alert.message}")

        # Auto-acknowledge if configured
        if auto_acknowledge and alert.severity == "info":
            monitor.acknowledge_alert(alert.id)
            alert_summary["processed"] += 1

    return alert_summary


# Helper functions

def _score_finding(finding: Dict[str, Any]) -> float:
    """
    Score a finding on 1-5 scale

    1 = definitely false positive
    2 = likely false positive
    3 = uncertain
    4 = likely valid
    5 = definitely valid

    Args:
        finding: Finding dictionary with severity and metadata

    Returns:
        Score 1.0-5.0
    """
    severity_scores = {
        "critical": 5.0,
        "high": 4.5,
        "medium": 4.0,
        "low": 3.0,
        "info": 1.5
    }

    severity = finding.get("severity", "medium").lower()
    base_score = severity_scores.get(severity, 3.0)

    # Adjust based on other factors if available
    if finding.get("secret_verified") == "true":
        base_score = min(5.0, base_score + 1.0)

    if finding.get("reachability") == "no":
        base_score = max(1.0, base_score - 1.0)

    return base_score


def _get_verdict(score: float) -> str:
    """
    Convert score to verdict

    Args:
        score: 1.0-5.0 score

    Returns:
        Verdict string
    """
    if score >= 4.5:
        return "definitely_valid"
    elif score >= 3.5:
        return "likely_valid"
    elif score >= 2.5:
        return "uncertain"
    elif score >= 1.5:
        return "likely_false_positive"
    else:
        return "definitely_false_positive"


if __name__ == "__main__":
    # Example usage
    logger.info("Audit Monitor Integration Example")
    logger.info("=" * 80)

    # Example: Generate dashboard report
    metrics = generate_dashboard_report(days=30)
    logger.info("\nDashboard Metrics:")
    print(json.dumps(metrics, indent=2))

    # Example: Analyze trends
    trends = analyze_audit_trends("test-repo", days=30)
    logger.info("\nAudit Trends:")
    print(json.dumps(trends, indent=2))

    # Example: Handle alerts
    alert_summary = handle_alerts(auto_acknowledge=True)
    logger.info("\nAlert Summary:")
    logger.info(f"  Total: {alert_summary['total']}")
    logger.info(f"  By Severity: {alert_summary['by_severity']}")
    logger.info(f"  Processed: {alert_summary['processed']}")
