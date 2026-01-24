#!/usr/bin/env python3
"""
Argus Metrics Dashboard Generator
Creates beautiful HTML dashboards from security scan results
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any


class DashboardGenerator:
    """Generate interactive HTML dashboards from scan results"""

    def __init__(self, results_dir: str = ".argus/reviews"):
        self.results_dir = Path(results_dir)
        self.metrics_file = self.results_dir / "metrics.json"
        self.findings_file = self.results_dir / "results.json"

    def generate(self, output_file: str = None) -> str:
        """Generate dashboard HTML"""
        if output_file is None:
            output_file = str(self.results_dir / "dashboard.html")

        # Load data
        metrics = self._load_metrics()
        findings = self._load_findings()

        # Generate HTML
        html = self._generate_html(metrics, findings)

        # Write file
        with open(output_file, "w") as f:
            f.write(html)

        return output_file

    def _load_metrics(self) -> dict[str, Any]:
        """Load metrics.json"""
        if not self.metrics_file.exists():
            return {
                "cost_usd": 0.0,
                "duration_seconds": 0,
                "files_reviewed": 0,
                "findings": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                "noise_suppressed": 0,
                "false_positive_rate": 0.0,
            }

        with open(self.metrics_file) as f:
            return json.load(f)

    def _load_findings(self) -> list[dict[str, Any]]:
        """Load findings from results.json"""
        if not self.findings_file.exists():
            return []

        with open(self.findings_file) as f:
            data = json.load(f)
            return data.get("findings", [])

    def _generate_html(self, metrics: dict, findings: list[dict]) -> str:
        """Generate complete HTML dashboard"""

        total_findings = sum(metrics.get("findings", {}).values())
        noise_suppressed = metrics.get("noise_suppressed", 0)
        noise_rate = (
            (noise_suppressed / (total_findings + noise_suppressed) * 100)
            if (total_findings + noise_suppressed) > 0
            else 0
        )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Argus Security Dashboard</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            color: #333;
        }}

        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}

        .header {{
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }}

        .header h1 {{
            font-size: 32px;
            color: #667eea;
            margin-bottom: 10px;
        }}

        .header .subtitle {{
            color: #666;
            font-size: 16px;
        }}

        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }}

        .metric-card {{
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            transition: transform 0.2s;
        }}

        .metric-card:hover {{
            transform: translateY(-5px);
        }}

        .metric-card .label {{
            color: #666;
            font-size: 14px;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 10px;
        }}

        .metric-card .value {{
            font-size: 36px;
            font-weight: bold;
            color: #333;
        }}

        .metric-card .subvalue {{
            color: #999;
            font-size: 14px;
            margin-top: 5px;
        }}

        .metric-card.critical {{
            border-left: 4px solid #dc3545;
        }}

        .metric-card.high {{
            border-left: 4px solid #fd7e14;
        }}

        .metric-card.medium {{
            border-left: 4px solid #ffc107;
        }}

        .metric-card.success {{
            border-left: 4px solid #28a745;
        }}

        .metric-card.info {{
            border-left: 4px solid #667eea;
        }}

        .chart-section {{
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }}

        .chart-section h2 {{
            font-size: 24px;
            margin-bottom: 20px;
            color: #333;
        }}

        .findings-table {{
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            overflow-x: auto;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
        }}

        th {{
            background: #f8f9fa;
            padding: 15px;
            text-align: left;
            font-weight: 600;
            color: #333;
            border-bottom: 2px solid #dee2e6;
        }}

        td {{
            padding: 15px;
            border-bottom: 1px solid #dee2e6;
        }}

        .severity {{
            display: inline-block;
            padding: 5px 10px;
            border-radius: 5px;
            font-size: 12px;
            font-weight: bold;
            text-transform: uppercase;
        }}

        .severity.critical {{
            background: #dc3545;
            color: white;
        }}

        .severity.high {{
            background: #fd7e14;
            color: white;
        }}

        .severity.medium {{
            background: #ffc107;
            color: #333;
        }}

        .severity.low {{
            background: #17a2b8;
            color: white;
        }}

        .bar-chart {{
            display: flex;
            align-items: flex-end;
            height: 200px;
            gap: 20px;
            margin: 20px 0;
        }}

        .bar {{
            flex: 1;
            background: linear-gradient(180deg, #667eea 0%, #764ba2 100%);
            border-radius: 5px 5px 0 0;
            position: relative;
            display: flex;
            flex-direction: column;
            justify-content: flex-end;
            align-items: center;
            color: white;
            font-weight: bold;
        }}

        .bar .bar-value {{
            position: absolute;
            top: -25px;
            font-size: 18px;
            color: #333;
        }}

        .bar .bar-label {{
            padding: 10px;
            font-size: 12px;
            text-align: center;
        }}

        .progress-ring {{
            transform: rotate(-90deg);
        }}

        .progress-circle {{
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 10px;
        }}

        .footer {{
            text-align: center;
            color: white;
            padding: 20px;
            font-size: 14px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Argus Security Dashboard</h1>
            <p class="subtitle">Generated on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        </div>

        <div class="metrics-grid">
            <div class="metric-card critical">
                <div class="label">Critical Findings</div>
                <div class="value">{metrics.get("findings", {}).get("critical", 0)}</div>
                <div class="subvalue">Requires immediate action</div>
            </div>

            <div class="metric-card high">
                <div class="label">High Priority</div>
                <div class="value">{metrics.get("findings", {}).get("high", 0)}</div>
                <div class="subvalue">Fix before release</div>
            </div>

            <div class="metric-card medium">
                <div class="label">Medium Priority</div>
                <div class="value">{metrics.get("findings", {}).get("medium", 0)}</div>
                <div class="subvalue">Address soon</div>
            </div>

            <div class="metric-card success">
                <div class="label">Noise Suppressed</div>
                <div class="value">{noise_suppressed}</div>
                <div class="subvalue">{noise_rate:.1f}% false positive reduction</div>
            </div>

            <div class="metric-card info">
                <div class="label">Files Analyzed</div>
                <div class="value">{metrics.get("files_reviewed", 0)}</div>
                <div class="subvalue">In {metrics.get("duration_seconds", 0):.1f} seconds</div>
            </div>

            <div class="metric-card info">
                <div class="label">Total Cost</div>
                <div class="value">${metrics.get("cost_usd", 0):.2f}</div>
                <div class="subvalue">AI analysis cost</div>
            </div>
        </div>

        <div class="chart-section">
            <h2>📊 Findings Distribution</h2>
            <div class="bar-chart">
                <div class="bar" style="height: {self._scale_height(metrics.get("findings", {}).get("critical", 0), metrics)}%">
                    <span class="bar-value">{metrics.get("findings", {}).get("critical", 0)}</span>
                    <span class="bar-label">Critical</span>
                </div>
                <div class="bar" style="height: {self._scale_height(metrics.get("findings", {}).get("high", 0), metrics)}%">
                    <span class="bar-value">{metrics.get("findings", {}).get("high", 0)}</span>
                    <span class="bar-label">High</span>
                </div>
                <div class="bar" style="height: {self._scale_height(metrics.get("findings", {}).get("medium", 0), metrics)}%">
                    <span class="bar-value">{metrics.get("findings", {}).get("medium", 0)}</span>
                    <span class="bar-label">Medium</span>
                </div>
                <div class="bar" style="height: {self._scale_height(metrics.get("findings", {}).get("low", 0), metrics)}%">
                    <span class="bar-value">{metrics.get("findings", {}).get("low", 0)}</span>
                    <span class="bar-label">Low</span>
                </div>
                <div class="bar" style="height: {self._scale_height(noise_suppressed, metrics)}%; background: linear-gradient(180deg, #28a745 0%, #20c997 100%)">
                    <span class="bar-value">{noise_suppressed}</span>
                    <span class="bar-label">Suppressed</span>
                </div>
            </div>
        </div>

        {self._generate_findings_table(findings)}

        <div class="footer">
            <p>Generated by Argus Code Reviewer</p>
            <p>🔒 AI-Powered Security Analysis with 60%+ False Positive Reduction</p>
        </div>
    </div>
</body>
</html>"""

    def _scale_height(self, value: int, metrics: dict) -> float:
        """Scale bar height to percentage (10-100%)"""
        all_values = list(metrics.get("findings", {}).values())
        all_values.append(metrics.get("noise_suppressed", 0))
        max_value = max(all_values) if all_values else 1

        if max_value == 0:
            return 0

        # Scale to 10-100% range
        percentage = (value / max_value) * 90 + 10
        return min(percentage, 100)

    def _generate_findings_table(self, findings: list[dict]) -> str:
        """Generate findings table HTML"""
        if not findings:
            return """
        <div class="findings-table">
            <h2>✅ No Security Findings</h2>
            <p>No critical security issues detected. Great job!</p>
        </div>"""

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        sorted_findings = sorted(findings, key=lambda x: severity_order.get(x.get("severity", "low").lower(), 99))

        rows = ""
        for finding in sorted_findings[:20]:  # Limit to top 20
            severity = finding.get("severity", "medium").lower()
            title = finding.get("title", "Unknown issue")
            file_path = finding.get("file", "Unknown")
            line = finding.get("line", "?")

            rows += f"""
            <tr>
                <td><span class="severity {severity}">{severity}</span></td>
                <td>{title}</td>
                <td>{file_path}</td>
                <td>{line}</td>
            </tr>"""

        return f"""
        <div class="findings-table">
            <h2>🔍 Top Findings</h2>
            <table>
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Finding</th>
                        <th>File</th>
                        <th>Line</th>
                    </tr>
                </thead>
                <tbody>
                    {rows}
                </tbody>
            </table>
        </div>"""


def main():
    """Generate dashboard from command line"""
    import sys

    results_dir = sys.argv[1] if len(sys.argv) > 1 else ".argus/reviews"
    output_file = sys.argv[2] if len(sys.argv) > 2 else None

    generator = DashboardGenerator(results_dir)
    dashboard_path = generator.generate(output_file)

    print(f"✅ Dashboard generated: {dashboard_path}")
    print(f"🌐 Open in browser: file://{os.path.abspath(dashboard_path)}")


if __name__ == "__main__":
    main()
