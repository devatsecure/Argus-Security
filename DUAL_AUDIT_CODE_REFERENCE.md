# Dual-Audit Code Reference - Complete Updated Sections

## File Location
`/Users/waseem.ahmed/Repos/argus-action/scripts/dual_audit.py`

---

## Section 1: Scoring Rubric Constants (Lines 23-75)

```python
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
```

---

## Section 2: Enhanced run_codex_validation() Method (Lines 146-274)

```python
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

    cmd = [
        "codex",
        "review",
        "--temperature", "0.2",
        codex_prompt
    ]

    try:
        result = subprocess.run(
            cmd,
            cwd=self.target_repo,
            capture_output=True,
            text=True,
            timeout=300
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
```

### Key Enhancements:
1. **Scoring Rubric Integration**: Includes formatted rubric in prompt (line 165)
2. **Chain-of-Thought Instructions**: 5-step reasoning process (lines 170-198)
3. **Structured Output Format**: Specific format for each finding (lines 221-230)
4. **Temperature Control**: `--temperature 0.2` parameter (line 246)
5. **Focus Areas**: Expanded security categories (lines 211-219)
6. **Assessment Categories**: Valid/Invalid/Uncertain options (line 205)

---

## Section 3: Enhanced _generate_findings_summary() Method (Lines 276-322)

```python
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
```

### Key Enhancements:
1. **Low Severity Included**: Shows complete severity distribution (line 289)
2. **Metrics Added**: Duration and cost information (lines 291-292)
3. **Top 15 Findings**: Increased from 10 for better coverage (line 296)
4. **CWE Information**: Includes CWE ID for each finding (line 301)
5. **Location Details**: File path and line number (lines 302-303)
6. **Validation Context**: Guidelines for Codex reviewer (lines 313-320)

---

## Section 4: New _format_scoring_rubric() Helper Method (Lines 324-337)

```python
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
```

### Purpose:
- Converts the `SCORING_RUBRIC` dictionary into readable text
- Displays all 5 levels in descending order
- Shows criteria for each level
- Integrates seamlessly into Codex prompt

### Output Example:
```
SCORE 5: Definitely Valid
Description: Confirmed vulnerability with clear evidence
Criteria:
  - Direct proof of vulnerability in code
  - Exploitable without edge cases
  - Matches known CVE or vulnerability pattern
  - Can be demonstrated in current codebase

SCORE 4: Likely Valid
...
```

---

## Section 5: Enhanced generate_comparison_report() Method Header (Lines 339-375)

```python
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
```

### Key Enhancements:
1. **Methodology Documentation**: Explains rigorous validation approach
2. **Scoring Rubric Inclusion**: Full rubric displayed in report
3. **Chain-of-Thought Explanation**: 5-step process documented
4. **Temperature Rationale**: Explains consistency benefits
5. **Transparency**: Makes validation logic visible to stakeholders

---

## Integration Points

### How These Sections Work Together

1. **SCORING_RUBRIC** (Lines 23-75)
   - Defines the validation criteria
   - Used by `_format_scoring_rubric()`
   - Referenced in Codex prompt

2. **_format_scoring_rubric()** (Lines 324-337)
   - Formats rubric for display
   - Called in `run_codex_validation()` (line 165)
   - Included in `generate_comparison_report()` (line 358)

3. **_generate_findings_summary()** (Lines 276-322)
   - Prepares findings for Codex review
   - Called in `run_codex_validation()` (line 159)
   - Includes validation context guidelines

4. **run_codex_validation()** (Lines 146-274)
   - Orchestrates validation process
   - Uses all above components
   - Applies temperature=0.2 for consistency

5. **generate_comparison_report()** (Lines 339-375)
   - Documents methodology in final report
   - References all validation improvements
   - Provides transparency to stakeholders

---

## Sample Output Structure

### Codex Validation Output Format

```
FINDING: SQL injection in user input handler at line 127
ASSESSMENT: Valid
SCORE: 5
JUSTIFICATION: Direct code evidence of unsanitized SQL query construction with user input. No parameterized queries used. Directly matches OWASP Top 10 2021 A03:2021 – Injection pattern.
EVIDENCE: query = f"SELECT * FROM users WHERE id = {user_id}" - user_id comes directly from request parameter without validation or sanitization.

FINDING: Hardcoded API key in configuration file
ASSESSMENT: Valid
SCORE: 5
JUSTIFICATION: Clear evidence of credentials in plaintext. Exploitable by anyone with code access. Matches CVE patterns for hardcoded secrets.
EVIDENCE: Line 45: API_KEY = "sk_live_abc123xyz789"

FINDING: Use of MD5 for password hashing
ASSESSMENT: Valid
SCORE: 4
JUSTIFICATION: Cryptographically broken algorithm. While exploitable, modern systems have better alternatives. Matches OWASP vulnerability pattern.
EVIDENCE: hash = hashlib.md5(password.encode()).hexdigest()

...

SUMMARY:
- Validated findings: 12
- Disputed findings: 2
- New findings: 3
- Estimated false positive rate: 15%
```

---

## Temperature Parameter Details

### Why temperature=0.2?

**Temperature Scale:**
- 0.0: Most deterministic (always same output)
- 0.2: Very consistent, minimal creativity (recommended for validation)
- 0.7: Moderate creativity (default for generation)
- 1.0+: High creativity/randomness

**Benefits for Validation:**
- **Reproducibility**: Same findings always get same assessment
- **Consistency**: Reduces variability in edge case decisions
- **Reliability**: Can be used in automated pipelines
- **Auditing**: Validation decisions are deterministic and explainable

---

## Usage Example

```bash
# Run enhanced dual audit
python scripts/dual_audit.py /path/to/repo --project-type backend-api

# Expected output includes:
# - Phase 1: Argus findings
# - Phase 2: Codex validation with structured scores
# - Comprehensive report with validation methodology
# - Confidence scores for each finding (1-5)
```

---

## Backward Compatibility

All enhancements maintain 100% backward compatibility:
- Same CLI interface
- Same directory structure
- Same file naming
- Enhanced output (additional sections in report)
- No breaking changes

---

## Testing Recommendations

```bash
# 1. Verify syntax
python3 -m py_compile scripts/dual_audit.py

# 2. Test with sample repo
python scripts/dual_audit.py /path/to/test/repo

# 3. Review generated reports
cat .argus/dual-audit/*/dual_audit_report.md

# 4. Check Codex validation output
cat .argus/dual-audit/*/codex_validation.txt
```

---

## Summary of Code Changes

| Section | Lines | Change | Impact |
|---------|-------|--------|--------|
| Scoring Rubric | 23-75 | NEW | Defines validation criteria |
| run_codex_validation() | 146-274 | ENHANCED | Adds chain-of-thought, rubric, temperature |
| _generate_findings_summary() | 276-322 | ENHANCED | More detailed context, validation guidelines |
| _format_scoring_rubric() | 324-337 | NEW | Formats rubric for display |
| generate_comparison_report() | 339-375 | ENHANCED | Documents validation methodology |

**Total Lines Changed**: ~180 lines of enhanced/new code
**Backward Compatibility**: 100% maintained
**Syntax Verification**: Passed ✓

