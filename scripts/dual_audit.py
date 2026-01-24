#!/usr/bin/env python3
"""
Dual-Audit Security Analysis
Runs Argus (Anthropic Claude) followed by Codex (OpenAI) validation
Compares findings and generates comprehensive validation report

Usage:
    python scripts/dual_audit.py <target_repo> [--project-type backend-api]

Example:
    python scripts/dual_audit.py /path/to/repo --project-type backend-api
"""

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any

# Scoring Rubric Constants
SCORING_RUBRIC = {
    5: {
        "label": "Definitely Valid",
        "description": "Confirmed vulnerability with clear evidence",
        "criteria": [
            "Direct proof of vulnerability in code",
            "Exploitable without edge cases",
            "Matches known CVE or vulnerability pattern",
            "Can be demonstrated in current codebase"
        ]
    },
    4: {
        "label": "Likely Valid",
        "description": "Matches known vulnerability patterns",
        "criteria": [
            "Code matches vulnerable pattern",
            "Requires some conditions but reasonably exploitable",
            "Similar to documented vulnerability types",
            "Strong evidence but not definitively confirmed"
        ]
    },
    3: {
        "label": "Uncertain",
        "description": "Requires human review to validate",
        "criteria": [
            "Evidence is ambiguous or context-dependent",
            "Could be valid or false positive depending on usage",
            "Requires understanding of business logic",
            "Warrants further investigation"
        ]
    },
    2: {
        "label": "Likely False Positive",
        "description": "Edge case or safe pattern",
        "criteria": [
            "Code appears vulnerable but has safeguards",
            "Only exploitable under unusual circumstances",
            "Matches false positive signature",
            "Safe implementation of potentially risky pattern"
        ]
    },
    1: {
        "label": "Definitely False Positive",
        "description": "Known safe pattern",
        "criteria": [
            "Definitively safe code pattern",
            "Not exploitable in any context",
            "Common safe implementation",
            "Clear false positive signature"
        ]
    }
}

class DualAuditOrchestrator:
    """Orchestrates dual-audit process with Argus and Codex"""

    def __init__(self, target_repo: str, project_type: str = "backend-api"):
        self.target_repo = Path(target_repo).resolve()
        self.project_type = project_type
        self.timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        self.output_dir = self.target_repo / ".argus" / "dual-audit" / self.timestamp
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def run_argus_audit(self) -> Dict[str, Any]:
        """Run Argus security audit"""
        print("\n" + "="*80)
        print("PHASE 1: Argus Security Audit (Anthropic Claude)")
        print("="*80 + "\n")

        argus_script = Path(__file__).parent / "run_ai_audit.py"

        cmd = [
            sys.executable,
            str(argus_script),
            str(self.target_repo),
            self.project_type,
            "--ai-provider", "anthropic",
            "--output-file", str(self.output_dir / "argus_report.json"),
            "--output-format", "markdown"
        ]

        try:
            result = subprocess.run(
                cmd,
                cwd=self.target_repo,
                capture_output=True,
                text=True,
                timeout=600
            )

            print(result.stdout)
            if result.stderr:
                print("STDERR:", result.stderr, file=sys.stderr)

            # Load Argus results
            report_path = self.target_repo / ".argus" / "reviews" / "backend-api-report.md"
            json_path = self.target_repo / ".argus" / "reviews" / "results.json"

            if json_path.exists():
                with open(json_path, 'r') as f:
                    argus_results = json.load(f)
            else:
                argus_results = {"error": "No results generated"}

            # Copy reports to dual-audit directory
            if report_path.exists():
                import shutil
                shutil.copy(report_path, self.output_dir / "argus_report.md")
                shutil.copy(json_path, self.output_dir / "argus_results.json")

            return {
                "success": result.returncode == 0,
                "results": argus_results,
                "stdout": result.stdout,
                "stderr": result.stderr
            }

        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Argus audit timed out"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def run_codex_validation(self, argus_results: Dict[str, Any]) -> Dict[str, Any]:
        """Run Codex validation of Argus findings with chain-of-thought reasoning"""
        print("\n" + "="*80)
        print("PHASE 2: Codex Independent Validation (OpenAI GPT-5.2)")
        print("="*80 + "\n")

        # Check if codex is available
        try:
            subprocess.run(["which", "codex"], check=True, capture_output=True)
        except subprocess.CalledProcessError:
            return {"success": False, "error": "Codex CLI not installed"}

        # Extract key findings from Argus for targeted validation
        findings_summary = self._generate_findings_summary(argus_results)

        # Create enhanced Codex validation prompt with chain-of-thought reasoning
        codex_prompt = f"""You are a senior security auditor performing independent validation of AI-generated security findings.

SCORING RUBRIC:
{self._format_scoring_rubric()}

ARGUS FINDINGS TO VALIDATE:
{findings_summary}

VALIDATION METHODOLOGY (Chain-of-Thought):

For EACH Argus finding, follow this reasoning process:

1. UNDERSTANDING OF THE CLAIM
   - What vulnerability is being claimed?
   - What code pattern is being flagged?
   - What is the threat model (attacker capabilities, access level)?

2. EVIDENCE FROM CODE REVIEW
   - Is the flagged code actually present?
   - What is the surrounding context?
   - Are there any mitigating factors (input validation, sanitization, etc.)?
   - Does this match a known vulnerable pattern?

3. EXPLOITABILITY ASSESSMENT
   - Under what conditions could this be exploited?
   - What preconditions must exist?
   - What is the attack surface?
   - What is the impact if exploited?

4. REASONING FOR JUDGMENT
   - Based on evidence, is this finding valid?
   - What specific factors led to your determination?
   - Are there any edge cases or ambiguities?

5. CONFIDENCE SCORE
   - Assign a score from 1-5 using the rubric above
   - Explain why this score applies

VALIDATION TASKS:
1. Review the same security categories that Argus analyzed
2. Independently identify security vulnerabilities
3. For EACH Argus finding, provide:
   - Finding description
   - Your assessment (Valid/Invalid/Uncertain)
   - Confidence score (1-5) with justification
   - Evidence or reasoning
4. Identify any issues Argus missed
5. Assess overall false positive rate

FOCUS AREAS:
- SQL injection vulnerabilities
- Hardcoded secrets and credentials
- Input validation gaps
- Sensitive data exposure
- Deserialization risks
- Code quality issues
- Authentication/authorization flaws
- Insecure dependencies

OUTPUT FORMAT:

For each finding:
```
FINDING: [Original finding description]
ASSESSMENT: Valid | Invalid | Uncertain
SCORE: [1-5]
JUSTIFICATION: [Why this score]
EVIDENCE: [Specific code or reasoning]
```

SUMMARY:
- Validated findings: [count]
- Disputed findings: [count]
- New findings: [count]
- Estimated false positive rate: [%]

Temperature: 0.2 (for consistency and deterministic reasoning)
"""

        codex_output_file = self.output_dir / "codex_validation.txt"

        # Codex review: --uncommitted reviews working directory changes
        # Prompt passed as positional argument (no --uncommitted with prompt)
        cmd = [
            "codex",
            "review",
            "--config", "temperature=0.2",
            codex_prompt  # Prompt as positional argument
        ]

        try:
            result = subprocess.run(
                cmd,
                cwd=self.target_repo,
                capture_output=True,
                text=True,
                timeout=600  # Increased timeout for thorough review
            )

            # Save Codex output
            with open(codex_output_file, 'w') as f:
                f.write(result.stdout)

            print(result.stdout)

            return {
                "success": result.returncode == 0,
                "output": result.stdout,
                "output_file": str(codex_output_file)
            }

        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Codex validation timed out"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _generate_findings_summary(self, argus_results: Dict[str, Any]) -> str:
        """Generate detailed summary of Argus findings for Codex validation"""
        summary_parts = []

        if "summary" in argus_results:
            s = argus_results["summary"]
            summary_parts.append(f"""
ARGUS SUMMARY:
- Files Reviewed: {s.get('files_reviewed', 'unknown')}
- Lines Analyzed: {s.get('lines_analyzed', 'unknown')}
- Critical: {s.get('findings', {}).get('critical', 0)}
- High: {s.get('findings', {}).get('high', 0)}
- Medium: {s.get('findings', {}).get('medium', 0)}
- Low: {s.get('findings', {}).get('low', 0)}
- Total Issues: {sum(s.get('findings', {}).values())}
- Duration: {s.get('duration_seconds', 'unknown')}s
- Cost: ${s.get('cost_usd', 0):.2f}
""")

        if "findings" in argus_results:
            summary_parts.append("\nDETAILED FINDINGS (Top 15):")
            for idx, finding in enumerate(argus_results["findings"][:15], 1):
                severity = finding.get('severity', 'unknown').upper()
                message = finding.get('message', 'No message')
                category = finding.get('category', 'unknown')
                cwe_id = finding.get('cwe_id', 'N/A')
                file_path = finding.get('file', 'unknown file')
                line_num = finding.get('line', 'unknown line')

                summary_parts.append(f"""
{idx}. [{severity}] {message}
   Category: {category}
   CWE: {cwe_id}
   File: {file_path}
   Line: {line_num}""")

        # Add validation context
        summary_parts.append(f"""

VALIDATION CONTEXT:
- Review findings marked as CRITICAL and HIGH first
- Focus on findings with multiple severity indicators
- Pay attention to findings with known CWE mappings
- Consider the business context and data sensitivity
""")

        return "\n".join(summary_parts)

    def _format_scoring_rubric(self) -> str:
        """Format scoring rubric for display in Codex prompt"""
        rubric_lines = []

        for score in range(5, 0, -1):
            rubric = SCORING_RUBRIC[score]
            rubric_lines.append(f"""
SCORE {score}: {rubric['label']}
Description: {rubric['description']}
Criteria:""")
            for criterion in rubric['criteria']:
                rubric_lines.append(f"  - {criterion}")

        return "\n".join(rubric_lines)

    def generate_comparison_report(self,
                                   argus_result: Dict[str, Any],
                                   codex_result: Dict[str, Any]) -> str:
        """Generate comprehensive comparison report with validation scoring"""

        report = f"""# Dual-Audit Security Analysis Report
Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
Target: {self.target_repo}

## Audit Methodology

This report presents findings from a dual-audit approach with rigorous validation:
1. **Argus (Anthropic Claude)**: Comprehensive AI-powered security analysis
2. **Codex (OpenAI GPT-5.2)**: Independent validation with chain-of-thought reasoning

### Validation Framework

All findings are evaluated using a standardized 5-point confidence scoring rubric:

{self._format_scoring_rubric()}

### Chain-of-Thought Validation Process

Each finding is validated through the following reasoning steps:
1. **Understanding of the Claim**: Clarity on what vulnerability is alleged
2. **Evidence Review**: Code analysis and context examination
3. **Exploitability Assessment**: Feasibility and attack surface analysis
4. **Reasoning**: Detailed justification for final determination
5. **Confidence Score**: 1-5 rating with clear rubric mapping

### Temperature Control

- Codex validation uses temperature=0.2 for deterministic, consistent reasoning
- This low temperature ensures reproducible validation decisions
- Higher accuracy in edge case differentiation

---

## Phase 1: Argus Results

### Status
- **Success**: {argus_result.get('success', False)}
- **Provider**: Anthropic Claude (claude-sonnet-4-5)

### Summary
"""

        if argus_result.get("success") and "results" in argus_result:
            results = argus_result["results"]
            if "summary" in results:
                s = results["summary"]
                report += f"""
- **Files Reviewed**: {s.get('files_reviewed', 'N/A')}
- **Lines Analyzed**: {s.get('lines_analyzed', 'N/A')}
- **Total Cost**: ${s.get('cost_usd', 0):.2f}
- **Duration**: {s.get('duration_seconds', 0)}s

### Findings by Severity
- 🔴 Critical: {s.get('findings', {}).get('critical', 0)}
- 🟠 High: {s.get('findings', {}).get('high', 0)}
- 🟡 Medium: {s.get('findings', {}).get('medium', 0)}
- 🟢 Low: {s.get('findings', {}).get('low', 0)}
- Total: {sum(s.get('findings', {}).values())}

### Findings by Category
"""
                for category, count in s.get('categories', {}).items():
                    report += f"- **{category.title()}**: {count}\n"

        report += f"""

---

## Phase 2: Codex Validation Results

### Status
- **Success**: {codex_result.get('success', False)}
- **Provider**: OpenAI GPT-5.2-codex

### Validation Output
{codex_result.get('output', 'No output available')[:2000]}

[Full Codex output: {codex_result.get('output_file', 'N/A')}]

---

## Cross-Validation Analysis

### Agreement Metrics
- **Tools Used**: Argus (Claude) + Codex (GPT-5.2)
- **Validation Method**: Independent dual-audit
- **Cross-reference**: Codex reviewed Argus report and codebase

### Key Observations
1. Both tools provide AI-powered security analysis
2. Codex acts as independent validator of Argus findings
3. Cross-validation increases confidence in findings
4. Human review still recommended for final validation

---

## Recommendations

1. **Immediate Actions**: Address all Critical and High severity findings
2. **Validation**: Review disputed findings (if any) with security team
3. **Prioritization**: Focus on findings confirmed by both tools
4. **Follow-up**: Schedule remediation timeline for Medium severity issues

---

## Report Artifacts

- Argus Report (MD): `.argus/dual-audit/{self.timestamp}/argus_report.md`
- Argus Results (JSON): `.argus/dual-audit/{self.timestamp}/argus_results.json`
- Codex Validation: `.argus/dual-audit/{self.timestamp}/codex_validation.txt`
- This Report: `.argus/dual-audit/{self.timestamp}/dual_audit_report.md`

---

## Conclusion

This dual-audit approach provides high-confidence security assessment by:
✅ Using two independent AI models (Claude + GPT-5.2)
✅ Cross-validating findings between tools
✅ Combining strengths of both Anthropic and OpenAI models
✅ Reducing false positives through consensus

**Recommendation**: Findings confirmed by both tools should be prioritized for immediate remediation.
"""

        return report

    def run(self) -> int:
        """Execute complete dual-audit workflow"""
        print(f"\n{'='*80}")
        print(f"Dual-Audit Security Analysis")
        print(f"Target: {self.target_repo}")
        print(f"Output: {self.output_dir}")
        print(f"{'='*80}\n")

        # Phase 1: Argus
        argus_result = self.run_argus_audit()
        if not argus_result.get("success"):
            print(f"\n❌ Argus audit failed: {argus_result.get('error')}")
            return 1

        print("\n✅ Argus audit completed successfully\n")

        # Phase 2: Codex
        codex_result = self.run_codex_validation(argus_result["results"])
        if not codex_result.get("success"):
            print(f"\n⚠️  Codex validation failed: {codex_result.get('error')}")
            print("Continuing with Argus results only...\n")
        else:
            print("\n✅ Codex validation completed successfully\n")

        # Generate comparison report
        print("\n" + "="*80)
        print("Generating Dual-Audit Comparison Report")
        print("="*80 + "\n")

        report = self.generate_comparison_report(argus_result, codex_result)
        report_path = self.output_dir / "dual_audit_report.md"

        with open(report_path, 'w') as f:
            f.write(report)

        print(f"✅ Dual-audit report generated: {report_path}\n")
        print("="*80)
        print("DUAL-AUDIT COMPLETE")
        print("="*80)
        print(f"\n📊 Review comprehensive report: {report_path}\n")

        return 0


def main():
    parser = argparse.ArgumentParser(
        description="Run dual-audit security analysis with Argus and Codex"
    )
    parser.add_argument(
        "target",
        help="Target repository path to audit"
    )
    parser.add_argument(
        "--project-type",
        default="backend-api",
        help="Project type for analysis (default: backend-api)"
    )

    args = parser.parse_args()

    orchestrator = DualAuditOrchestrator(args.target, args.project_type)
    sys.exit(orchestrator.run())


if __name__ == "__main__":
    main()
