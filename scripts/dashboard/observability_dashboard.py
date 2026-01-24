#!/usr/bin/env python3
"""
Argus Observability Dashboard
Streamlit dashboard for visualizing AI decision quality and system metrics

Features:
- Real-time decision quality metrics
- Feedback statistics and trends
- Scanner performance comparison
- Cost tracking and projections
- Pattern discovery visualization
"""

import json
import sys
from datetime import datetime, timedelta
from pathlib import Path

# Add parent directory to path for imports
SCRIPT_DIR = Path(__file__).parent.parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import streamlit as st

try:
    from decision_analyzer import DecisionAnalyzer
    from feedback_collector import FeedbackCollector
    from cache_manager import CacheManager
except ImportError as e:
    st.error(f"Failed to import required modules: {e}")
    st.stop()


def load_data():
    """Load data from decision log and feedback"""
    analyzer = DecisionAnalyzer()
    collector = FeedbackCollector()
    cache_mgr = CacheManager()

    # Load decisions
    decisions = analyzer.load_decisions()

    # Load feedback
    feedback = collector.get_all_feedback()

    # Get cache stats
    cache_stats = cache_mgr.get_cache_stats()

    return decisions, feedback, cache_stats, analyzer, collector


def render_overview(decisions, feedback, cache_stats):
    """Render overview metrics"""
    st.header("📊 Overview")

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric("Total Decisions", len(decisions))

    with col2:
        st.metric("User Feedback", len(feedback))

    with col3:
        cache_hit_rate = cache_stats.get("hit_rate", 0) * 100
        st.metric("Cache Hit Rate", f"{cache_hit_rate:.1f}%")

    with col4:
        cache_size_mb = cache_stats.get("total_size_mb", 0)
        st.metric("Cache Size", f"{cache_size_mb:.1f} MB")


def render_decision_metrics(analyzer, decisions):
    """Render decision quality metrics"""
    st.header("🤖 AI Decision Quality")

    if not decisions:
        st.info("No decisions logged yet. Run a security scan with AI triage to see metrics.")
        return

    analysis = analyzer.analyze_decisions(decisions)

    # Metrics row
    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric(
            "Suppression Rate",
            f"{analysis['suppression_rate']:.1f}%",
            help="Percentage of findings suppressed by AI"
        )

    with col2:
        st.metric(
            "Avg Confidence",
            f"{analysis['avg_confidence']:.3f}",
            help="Average confidence score (0-1)"
        )

    with col3:
        st.metric(
            "Low Confidence",
            analysis['low_confidence_count'],
            help="Decisions with confidence < 0.6"
        )

    # Confidence distribution chart
    st.subheader("Confidence Distribution")

    conf_dist = analysis.get("confidence_distribution", {})
    if conf_dist:
        import pandas as pd

        df = pd.DataFrame([
            {"Range": k, "Count": v}
            for k, v in conf_dist.items()
        ])

        st.bar_chart(df.set_index("Range"))

    # By scanner breakdown
    st.subheader("By Scanner")

    scanner_stats = analysis.get("by_scanner", {})
    if scanner_stats:
        scanner_data = []
        for scanner, stats in scanner_stats.items():
            suppress_rate = (stats["suppress"] / stats["total"] * 100) if stats["total"] > 0 else 0
            scanner_data.append({
                "Scanner": scanner,
                "Total": stats["total"],
                "Suppressed": stats["suppress"],
                "Escalated": stats["escalate"],
                "Suppression %": f"{suppress_rate:.1f}%"
            })

        import pandas as pd
        df = pd.DataFrame(scanner_data)
        st.dataframe(df, use_container_width=True)


def render_feedback_metrics(collector, feedback):
    """Render feedback statistics"""
    st.header("📝 User Feedback")

    if not feedback:
        st.info("No feedback recorded yet. Use 'argus feedback record' to mark findings as TP/FP.")
        return

    stats = collector.get_feedback_stats()

    # Metrics row
    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric(
            "Total Feedback",
            stats["total_feedback"]
        )

    with col2:
        st.metric(
            "False Positive Rate",
            f"{stats['fp_rate']:.1f}%",
            help="Percentage of findings marked as false positives"
        )

    with col3:
        st.metric(
            "True Positive Rate",
            f"{stats['tp_rate']:.1f}%",
            help="Percentage of findings marked as true positives"
        )

    # By scanner breakdown
    st.subheader("False Positive Rate by Scanner")

    by_scanner = stats.get("by_scanner", {})
    if by_scanner:
        scanner_data = []
        for scanner, scanner_stats in by_scanner.items():
            fp_rate = (scanner_stats["fp"] / scanner_stats["total"] * 100) if scanner_stats["total"] > 0 else 0
            scanner_data.append({
                "Scanner": scanner,
                "Total Feedback": scanner_stats["total"],
                "False Positives": scanner_stats["fp"],
                "FP Rate": fp_rate
            })

        import pandas as pd
        df = pd.DataFrame(scanner_data)

        # Sort by FP rate descending
        df = df.sort_values("FP Rate", ascending=False)

        st.dataframe(df, use_container_width=True)

        # Bar chart of FP rates
        import plotly.express as px
        fig = px.bar(
            df,
            x="Scanner",
            y="FP Rate",
            title="False Positive Rate by Scanner",
            color="FP Rate",
            color_continuous_scale="Reds"
        )
        st.plotly_chart(fig, use_container_width=True)


def render_patterns(analyzer, decisions):
    """Render discovered patterns"""
    st.header("🔍 Discovered Patterns")

    if not decisions:
        st.info("No decisions to analyze yet.")
        return

    patterns = analyzer.identify_patterns(decisions)

    if not patterns:
        st.info("No patterns discovered yet. More data needed.")
        return

    for i, pattern in enumerate(patterns, 1):
        with st.expander(f"Pattern {i}: {pattern.description}"):
            col1, col2 = st.columns(2)

            with col1:
                st.metric("Frequency", pattern.frequency)

            with col2:
                st.metric("Confidence", f"{pattern.confidence:.3f}")

            st.write(f"**Type:** `{pattern.pattern_type}`")

            if pattern.examples:
                st.write("**Example Decisions:**")
                for example in pattern.examples[:3]:
                    st.json(example)


def render_recommendations(analyzer, decisions, feedback):
    """Render improvement suggestions"""
    st.header("💡 Improvement Suggestions")

    if not decisions:
        st.info("No decisions to analyze yet.")
        return

    analysis = analyzer.analyze_decisions(decisions)
    patterns = analyzer.identify_patterns(decisions)
    suggestions = analyzer.suggest_improvements(analysis, patterns)

    if not suggestions:
        st.success("✅ No improvements needed! System is performing well.")
        return

    for i, suggestion in enumerate(suggestions, 1):
        st.info(f"{i}. {suggestion}")


def render_time_series(decisions, feedback):
    """Render time series charts"""
    st.header("📈 Trends Over Time")

    if not decisions and not feedback:
        st.info("No data to visualize yet.")
        return

    # Decision volume over time
    if decisions:
        st.subheader("Decision Volume")

        from collections import Counter
        import pandas as pd

        # Extract dates
        dates = []
        for d in decisions:
            try:
                timestamp = d.get("timestamp", "")
                date = datetime.fromisoformat(timestamp).date()
                dates.append(date)
            except:
                continue

        if dates:
            date_counts = Counter(dates)
            df = pd.DataFrame([
                {"Date": date, "Decisions": count}
                for date, count in sorted(date_counts.items())
            ])

            st.line_chart(df.set_index("Date"))

    # Feedback volume over time
    if feedback:
        st.subheader("Feedback Volume")

        from collections import Counter
        import pandas as pd

        dates = []
        for f in feedback:
            try:
                timestamp = f.get("timestamp", "")
                date = datetime.fromisoformat(timestamp).date()
                dates.append(date)
            except:
                continue

        if dates:
            date_counts = Counter(dates)
            df = pd.DataFrame([
                {"Date": date, "Feedback": count}
                for date, count in sorted(date_counts.items())
            ])

            st.line_chart(df.set_index("Date"))


def render_cache_stats(cache_stats):
    """Render cache statistics"""
    st.header("💾 Cache Performance")

    if not cache_stats.get("total_entries"):
        st.info("No cache data yet.")
        return

    # Metrics
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric("Total Entries", cache_stats.get("total_entries", 0))

    with col2:
        st.metric("Cache Hits", cache_stats.get("hits", 0))

    with col3:
        st.metric("Cache Misses", cache_stats.get("misses", 0))

    with col4:
        hit_rate = cache_stats.get("hit_rate", 0) * 100
        st.metric("Hit Rate", f"{hit_rate:.1f}%")

    # Per-scanner stats
    scanner_stats = cache_stats.get("scanners", {})
    if scanner_stats:
        st.subheader("Cache by Scanner")

        import pandas as pd

        scanner_data = []
        for scanner, stats in scanner_stats.items():
            scanner_data.append({
                "Scanner": scanner,
                "Entries": stats["entries"],
                "Size (MB)": stats["size_mb"]
            })

        df = pd.DataFrame(scanner_data)
        st.dataframe(df, use_container_width=True)


def main():
    """Main dashboard application"""
    st.set_page_config(
        page_title="Argus Observability",
        page_icon="🔒",
        layout="wide",
        initial_sidebar_state="expanded"
    )

    st.title("🔒 Argus Observability Dashboard")
    st.markdown("Real-time insights into AI decision quality, feedback, and system performance")

    # Sidebar controls
    with st.sidebar:
        st.header("⚙️ Controls")

        # Refresh button
        if st.button("🔄 Refresh Data", use_container_width=True):
            st.cache_data.clear()
            st.rerun()

        st.divider()

        # Date range filter
        st.subheader("Date Range")
        days_back = st.slider(
            "Days to analyze",
            min_value=1,
            max_value=90,
            value=30,
            help="Analyze data from the last N days"
        )

        st.divider()

        # Info
        st.info(
            "💡 **Tip:** Run security scans with AI triage to populate this dashboard.\n\n"
            "```bash\n"
            "python scripts/run_ai_audit.py \\\n"
            "  --project-type backend-api \\\n"
            "  --ai-provider anthropic\n"
            "```"
        )

    # Load data
    try:
        with st.spinner("Loading data..."):
            decisions, feedback, cache_stats, analyzer, collector = load_data()

        # Filter by date range
        start_date = datetime.now() - timedelta(days=days_back)
        decisions = [
            d for d in decisions
            if datetime.fromisoformat(d.get("timestamp", "")) >= start_date
        ]
        feedback = [
            f for f in feedback
            if datetime.fromisoformat(f.get("timestamp", "")) >= start_date
        ]

        # Render sections
        render_overview(decisions, feedback, cache_stats)
        st.divider()

        render_decision_metrics(analyzer, decisions)
        st.divider()

        render_feedback_metrics(collector, feedback)
        st.divider()

        render_patterns(analyzer, decisions)
        st.divider()

        render_recommendations(analyzer, decisions, feedback)
        st.divider()

        render_time_series(decisions, feedback)
        st.divider()

        render_cache_stats(cache_stats)

    except Exception as e:
        st.error(f"❌ Error loading data: {e}")
        st.exception(e)


if __name__ == "__main__":
    main()
