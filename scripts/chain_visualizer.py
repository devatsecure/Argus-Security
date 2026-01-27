#!/usr/bin/env python3
"""
Vulnerability Chain Visualizer
Generates visual reports and graphs for vulnerability chains

Author: Argus Security Team
License: MIT
"""

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


class ChainVisualizer:
    """Generate visual representations of vulnerability chains"""
    
    def __init__(self):
        """Initialize visualizer"""
        self.color_map = {
            'critical': '\033[91m',  # Red
            'high': '\033[93m',      # Yellow
            'medium': '\033[94m',    # Blue
            'low': '\033[92m',       # Green
            'info': '\033[90m',      # Gray
            'reset': '\033[0m',      # Reset
        }
    
    def generate_markdown_report(self, chains_data: dict, output_file: str):
        """Generate comprehensive Markdown report"""
        
        md = []
        
        # Header
        md.append("# 🔗 Vulnerability Chaining Analysis Report\n")
        md.append(f"**Generated:** {chains_data['timestamp']}")
        md.append(f"**Analysis Duration:** {chains_data['duration_seconds']:.1f}s\n")
        
        # Executive Summary
        md.append("## 📊 Executive Summary\n")
        stats = chains_data['statistics']
        md.append(f"- **Total Vulnerabilities Analyzed:** {chains_data['total_vulnerabilities']}")
        md.append(f"- **Attack Chains Discovered:** {chains_data['total_chains']}")
        md.append(f"- **Critical Chains:** {stats.get('critical_chains', 0)}")
        md.append(f"- **High-Risk Chains:** {stats.get('high_chains', 0)}")
        md.append(f"- **Average Chain Length:** {stats.get('avg_chain_length', 0):.1f} vulnerabilities")
        md.append(f"- **Average Risk Score:** {stats.get('avg_risk_score', 0):.1f}/10.0")
        md.append(f"- **Maximum Risk Score:** {stats.get('max_risk_score', 0):.1f}/10.0\n")
        
        # Risk Distribution
        md.append("## 🎯 Risk Distribution\n")
        md.append("| Exploitability | Count |")
        md.append("|----------------|-------|")
        for exploitability, count in stats.get('by_exploitability', {}).items():
            md.append(f"| {exploitability.title()} | {count} |")
        md.append("")
        
        # Detailed Chains
        md.append("## 🔗 Discovered Attack Chains\n")
        
        for i, chain in enumerate(chains_data['chains'][:10], 1):  # Top 10
            md.append(f"### Chain #{i}: Risk Score {chain['risk_score']:.1f}/10.0\n")
            
            # Chain metadata
            md.append(f"**Exploitability:** `{chain['exploitability']}` | "
                     f"**Complexity:** `{chain['complexity']}` | "
                     f"**Est. Exploit Time:** `{chain.get('estimated_exploit_time', 'Unknown')}`\n")
            
            # Amplification info
            md.append(f"**Base Risk:** {chain['base_risk']:.1f} → "
                     f"**Amplified Risk:** {chain['risk_score']:.1f} "
                     f"(×{chain['amplification_factor']:.2f} multiplier)\n")
            
            # Attack scenario
            md.append("#### 🎭 Attack Scenario\n")
            md.append("```")
            for j, vuln in enumerate(chain['vulnerabilities'], 1):
                arrow = "    ↓" if j < len(chain['vulnerabilities']) else ""
                md.append(f"Step {j}: {vuln['category']} [{vuln['severity'].upper()}]")
                md.append(f"  📁 File: {vuln['file_path']}")
                md.append(f"  📝 {vuln['title']}")
                if arrow:
                    md.append(arrow)
            md.append("```\n")
            
            # Final impact
            if chain.get('final_impact'):
                md.append(f"**💥 Final Impact:** {chain['final_impact']}\n")
            
            # Remediation priority
            md.append(f"**🎯 Mitigation Priority:** {chain.get('mitigation_priority', 5)}/10\n")
            
            md.append("---\n")
        
        # Save report
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w') as f:
            f.write('\n'.join(md))
        
        logger.info(f"   📄 Markdown report saved to: {output_path}")
    
    def print_console_report(self, chains_data: dict, max_chains: int = 5):
        """Print formatted report to console"""
        
        print("\n" + "=" * 80)
        print("🔗 VULNERABILITY CHAINING ANALYSIS REPORT")
        print("=" * 80)
        
        # Statistics
        stats = chains_data['statistics']
        print(f"\n📊 Statistics:")
        print(f"   Total Vulnerabilities: {chains_data['total_vulnerabilities']}")
        print(f"   Attack Chains Found: {chains_data['total_chains']}")
        print(f"   Critical Chains: {self._color('critical', stats.get('critical_chains', 0))}")
        print(f"   High-Risk Chains: {self._color('high', stats.get('high_chains', 0))}")
        print(f"   Avg Chain Length: {stats.get('avg_chain_length', 0):.1f}")
        print(f"   Avg Risk Score: {stats.get('avg_risk_score', 0):.1f}/10.0")
        
        # Top chains
        print(f"\n🔗 Top {min(max_chains, len(chains_data['chains']))} Attack Chains:")
        print("=" * 80)
        
        for i, chain in enumerate(chains_data['chains'][:max_chains], 1):
            self._print_chain(i, chain)
    
    def _print_chain(self, index: int, chain: dict):
        """Print a single chain"""
        risk_color = self._get_risk_color(chain['risk_score'])
        
        print(f"\n{risk_color}Chain #{index}: Risk {chain['risk_score']:.1f}/10.0{self.color_map['reset']}")
        print(f"Exploitability: {chain['exploitability'].title()} | "
              f"Complexity: {chain['complexity'].title()} | "
              f"Time: {chain.get('estimated_exploit_time', 'Unknown')}")
        print(f"Amplification: {chain['base_risk']:.1f} → {chain['risk_score']:.1f} "
              f"(×{chain['amplification_factor']:.2f})")
        
        print("\n🎭 Attack Flow:")
        for j, vuln in enumerate(chain['vulnerabilities'], 1):
            severity_color = self._get_severity_color(vuln['severity'])
            arrow = "    ↓" if j < len(chain['vulnerabilities']) else ""
            
            print(f"  {severity_color}Step {j}: {vuln['category']} [{vuln['severity'].upper()}]{self.color_map['reset']}")
            print(f"  📁 {vuln['file_path']}")
            print(f"  📝 {vuln['title'][:70]}...")
            if arrow:
                print(arrow)
        
        if chain.get('final_impact'):
            print(f"\n💥 Impact: {chain['final_impact']}")
        
        print("-" * 80)
    
    def _color(self, severity: str, text: Any) -> str:
        """Apply color to text"""
        return f"{self.color_map.get(severity, '')}{text}{self.color_map['reset']}"
    
    def _get_risk_color(self, risk_score: float) -> str:
        """Get color based on risk score"""
        if risk_score >= 9.0:
            return self.color_map['critical']
        elif risk_score >= 7.0:
            return self.color_map['high']
        elif risk_score >= 5.0:
            return self.color_map['medium']
        else:
            return self.color_map['low']
    
    def _get_severity_color(self, severity: str) -> str:
        """Get color based on severity"""
        return self.color_map.get(severity.lower(), self.color_map['reset'])
    
    def generate_ascii_graph(self, chain: dict) -> str:
        """Generate ASCII art graph for a chain"""
        lines = []
        
        lines.append("┌─────────────────────────────────────────┐")
        lines.append(f"│ Attack Chain: Risk {chain['risk_score']:.1f}/10.0")
        lines.append("└─────────────────────────────────────────┘")
        
        for i, vuln in enumerate(chain['vulnerabilities']):
            # Vulnerability box
            lines.append("│")
            lines.append(f"├─▶ [{vuln['severity'].upper()}] {vuln['category']}")
            lines.append(f"│   📁 {vuln['file_path']}")
            
            # Arrow to next
            if i < len(chain['vulnerabilities']) - 1:
                lines.append("│")
                lines.append("▼")
        
        lines.append("│")
        lines.append(f"└─▶ 💥 {chain.get('final_impact', 'High Impact')}")
        
        return "\n".join(lines)
    
    def generate_json_summary(self, chains_data: dict, output_file: str):
        """Generate JSON summary suitable for dashboards"""
        
        summary = {
            'metadata': {
                'timestamp': chains_data['timestamp'],
                'duration_seconds': chains_data['duration_seconds'],
            },
            'summary': {
                'total_vulnerabilities': chains_data['total_vulnerabilities'],
                'total_chains': chains_data['total_chains'],
                'critical_chains': chains_data['statistics'].get('critical_chains', 0),
                'high_risk_chains': chains_data['statistics'].get('high_chains', 0),
            },
            'top_chains': [
                {
                    'chain_id': chain['chain_id'],
                    'risk_score': chain['risk_score'],
                    'exploitability': chain['exploitability'],
                    'complexity': chain['complexity'],
                    'chain_length': chain['chain_length'],
                    'final_impact': chain.get('final_impact', ''),
                    'vulnerabilities': [
                        {
                            'category': v['category'],
                            'severity': v['severity'],
                            'file': v['file_path'],
                        }
                        for v in chain['vulnerabilities']
                    ]
                }
                for chain in chains_data['chains'][:10]
            ],
            'statistics': chains_data['statistics'],
        }
        
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w') as f:
            json.dump(summary, f, indent=2)
        
        logger.info(f"   📊 JSON summary saved to: {output_path}")


def main():
    """CLI entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Vulnerability Chain Visualizer")
    parser.add_argument('--input', '-i', required=True, help='Input chains JSON file')
    parser.add_argument('--output-md', help='Output Markdown report file')
    parser.add_argument('--output-json', help='Output JSON summary file')
    parser.add_argument('--console', action='store_true', help='Print to console')
    parser.add_argument('--max-chains', type=int, default=5, help='Max chains to show')
    
    args = parser.parse_args()
    
    # Load chains data
    with open(args.input) as f:
        chains_data = json.load(f)
    
    visualizer = ChainVisualizer()
    
    # Generate outputs
    if args.output_md:
        visualizer.generate_markdown_report(chains_data, args.output_md)
        print(f"\n✅ Markdown report: {args.output_md}")
    
    if args.output_json:
        visualizer.generate_json_summary(chains_data, args.output_json)
        print(f"✅ JSON summary: {args.output_json}")
    
    if args.console or (not args.output_md and not args.output_json):
        visualizer.print_console_report(chains_data, args.max_chains)
    
    return 0


if __name__ == "__main__":
    exit(main())
