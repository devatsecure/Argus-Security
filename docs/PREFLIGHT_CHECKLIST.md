# Pre-Flight Checklist System

## Overview

The Pre-Flight Checklist System provides **human-in-the-loop approval** before submitting security reports externally. This prevents automated spam and ensures high-quality submissions to open-source projects.

## Why This Exists

**Problem:** Automated security scanners can generate low-quality reports with:
- Empty or "unknown" file paths
- Missing line numbers
- Generic "Unknown Issue" titles
- No remediation guidance
- False positives

**Solution:** The Pre-Flight Checklist enforces quality standards and requires human confirmation before external submission.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    SECURITY REPORT                           │
│                   (findings.json)                            │
└───────────────────────────┬─────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│           PREFLIGHT CHECKER (preflight_checker.py)          │
│                                                              │
│  ┌────────────────────────────────────────────────────┐    │
│  │          AUTOMATED CHECKS                          │    │
│  │  • Quality score >= 80                             │    │
│  │  • All findings have file paths                    │    │
│  │  • All findings have line numbers                  │    │
│  │  • All findings have severity                      │    │
│  └────────────────────┬───────────────────────────────┘    │
│                       │                                      │
│                       ▼                                      │
│                   ┌───────┐                                 │
│                   │ PASS? │                                 │
│                   └───┬───┘                                 │
│                       │                                      │
│              ┌────────┴────────┐                            │
│              │ YES             │ NO                          │
│              ▼                 ▼                             │
│  ┌──────────────────┐  ┌─────────────────┐                │
│  │  MANUAL CHECKS   │  │  BLOCK & EXIT   │                │
│  │  (Interactive)   │  └─────────────────┘                │
│  │  • Contact ID'd? │                                       │
│  │  • Method set?   │                                       │
│  │  • Timeline OK?  │                                       │
│  │  • Human review? │                                       │
│  └────────┬─────────┘                                       │
│           │                                                  │
│           ▼                                                  │
│      ┌────────┐                                             │
│      │ PASS?  │                                             │
│      └───┬────┘                                             │
│          │                                                   │
│   ┌──────┴──────┐                                           │
│   │ YES         │ NO                                        │
│   ▼             ▼                                            │
│ ┌──────┐   ┌─────────┐                                     │
│ │APPROVE│  │ BLOCK   │                                     │
│ └───────┘  └─────────┘                                     │
└─────────────────────────────────────────────────────────────┘
           │
           ▼
┌─────────────────────────────────────────────────────────────┐
│                    AUDIT TRAIL                               │
│  • preflight_results.json (machine-readable)                │
│  • preflight_checklist.md (human-readable)                  │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

### 1. Basic Usage

```bash
# Interactive mode (with manual confirmation prompts)
python scripts/preflight_checker.py --report findings.json

# Non-interactive mode (automated checks only, for CI)
python scripts/preflight_checker.py --report findings.json --non-interactive

# Custom checklist
python scripts/preflight_checker.py --report findings.json --checklist custom.yml
```

### 2. Exit Codes

- **0** - All checks passed, approved for submission
- **1** - Checks failed, NOT approved for submission

### 3. Output Files

The checker generates two files alongside your report:

```
findings.json                          # Your original report
findings_preflight_results.json        # Machine-readable audit trail
findings_preflight_checklist.md        # Human-readable checklist
```

## Automated Checks

These run automatically without human interaction:

| Check | Description | Points Lost if Failed |
|-------|-------------|----------------------|
| **Quality Score >= 80** | Overall report quality from `report_quality_validator.py` | CRITICAL |
| **File Paths Present** | All findings have valid file paths (not "unknown") | CRITICAL |
| **Line Numbers Present** | All findings have line numbers >= 1 | CRITICAL |
| **Severity Assigned** | All findings have valid severity levels | HIGH |

**Note:** If any automated check fails, the checker blocks submission immediately without proceeding to manual checks.

## Manual Checks

These require human confirmation (yes/no):

1. **Security contact identified?**
   - Have you found the project's security contact (SECURITY.md, email)?

2. **Disclosure method selected?**
   - Email, GitHub Security Advisory, HackerOne, Bugcrowd?

3. **90-day timeline agreed?**
   - Coordinated disclosure timeline negotiated with maintainers?

4. **Human reviewed report?**
   - Did a human review the report for quality and accuracy?

5. **Report readability tested?**
   - Can a developer understand and fix the issues?

6. **NOT a public disclosure?**
   - Confirmed this is NOT being posted publicly (GitHub issue, blog, tweet)?

7. **Findings verified?**
   - Verified findings are NOT false positives?

8. **Reproduction steps included?**
   - Proof-of-concept or repro steps for critical/high findings?

9. **Impact documented?**
   - Business impact and attack scenarios for high-severity findings?

10. **Remediation guidance provided?**
    - Actionable fix recommendations for all findings?

## Configuration

### Default Checklist: `.argus/preflight-checklist.yml`

```yaml
automated_checks:
  - name: "Quality score ≥ 80"
    validator: "quality_score_validator"

  - name: "All findings have file paths"
    validator: "file_path_validator"

  - name: "All findings have line numbers"
    validator: "line_number_validator"

  - name: "All findings have valid severity"
    validator: "severity_validator"

manual_checks:
  - "Security contact identified?"
  - "Disclosure method selected?"
  - "90-day timeline agreed with maintainers?"
  - "Human reviewed report for quality and accuracy?"
  - "Test report readability (can a developer action it)?"
  - "Confirmed this is NOT a public security disclosure?"
  - "Verified findings are NOT false positives?"
  - "Reproduction steps included for critical/high findings?"
  - "Impact documented for high-severity findings?"
  - "Remediation guidance provided for all findings?"
```

### Custom Validators

You can add custom command validators:

```yaml
automated_checks:
  - name: "SARIF format is valid"
    command: "sarif-validator {report}"
    description: "Validates SARIF structure"

  - name: "Spell check passed"
    command: "codespell {report}"
    description: "No spelling errors in report"
```

### Built-in Validators

The following validators are available:

| Validator | Purpose |
|-----------|---------|
| `quality_score_validator` | Checks `summary.quality_score >= 80` |
| `file_path_validator` | Ensures all findings have valid `file_path` |
| `line_number_validator` | Ensures all findings have `line_number >= 1` |
| `severity_validator` | Ensures all findings have valid severity level |

## Example Output

### Passing Checklist

```
======================================================================
ARGUS SECURITY PRE-FLIGHT CHECKLIST
======================================================================
Report: findings.json

======================================================================
AUTOMATED CHECKS
======================================================================

✅ PASS - Quality score ≥ 80
      Quality score: 85

✅ PASS - All findings have file paths
      All 3 findings have file paths

✅ PASS - All findings have line numbers
      All 3 findings have line numbers

✅ PASS - All findings have valid severity
      All 3 findings have valid severity

======================================================================
MANUAL CHECKS (Human Confirmation Required)
======================================================================

Security contact identified?
  Confirm (yes/no): yes
  ✅ Confirmed

Disclosure method selected (email/private issue/HackerOne)?
  Confirm (yes/no): yes
  ✅ Confirmed

...

======================================================================
✅ PRE-FLIGHT CHECKLIST PASSED
======================================================================
Report is approved for external submission.

Checklist results saved to: findings_preflight_results.json
Markdown checklist saved to: findings_preflight_checklist.md
```

### Failing Checklist

```
======================================================================
ARGUS SECURITY PRE-FLIGHT CHECKLIST
======================================================================
Report: bad_findings.json

======================================================================
AUTOMATED CHECKS
======================================================================

❌ FAIL - Quality score ≥ 80
      Quality score too low: 45 (minimum: 80)

❌ FAIL - All findings have file paths
      Findings missing file paths: [1, 3, 5] (+2 more)

❌ FAIL - All findings have line numbers
      Findings missing line numbers: [2, 4, 6]

✅ PASS - All findings have valid severity
      All 8 findings have valid severity

======================================================================
AUTOMATED CHECKS FAILED
======================================================================
Fix the automated check failures before proceeding.

Checklist results saved to: bad_findings_preflight_results.json
Markdown checklist saved to: bad_findings_preflight_checklist.md
```

## Integration with Argus Pipelines

### Phase 6 Integration (External Reporting)

Add pre-flight check before external submission:

```python
from scripts.preflight_checker import PreFlightChecker

# Generate report
report_path = generate_report(findings)

# Run pre-flight checklist
checker = PreFlightChecker(
    report_path=report_path,
    non_interactive=False  # Require human approval
)

if checker.run():
    print("✅ Report approved for submission")
    submit_to_external_repo(report_path)
else:
    print("❌ Report blocked - quality issues detected")
    sys.exit(1)
```

### CI/CD Integration

For automated pipelines, use non-interactive mode:

```bash
# GitHub Actions
- name: Pre-flight Checklist
  run: |
    python scripts/preflight_checker.py \
      --report .argus/reviews/results.json \
      --non-interactive
  continue-on-error: false
```

### Manual Workflow

```bash
# 1. Generate security report
python scripts/run_ai_audit.py --target external-repo

# 2. Run pre-flight checklist
python scripts/preflight_checker.py \
  --report .argus/reviews/results.json

# 3. If approved, submit report
# (manual process: email, GitHub Security Advisory, etc.)
```

## Audit Trail

### JSON Output (`preflight_results.json`)

```json
{
  "automated_checks": [
    {
      "name": "Quality score ≥ 80",
      "passed": true,
      "message": "Quality score: 85"
    },
    ...
  ],
  "manual_checks": [
    {
      "question": "Security contact identified?",
      "confirmed": true
    },
    ...
  ],
  "timestamp": "2026-01-29T11:29:47Z",
  "report_path": "findings.json",
  "user": "waseem.ahmed",
  "passed": true
}
```

### Markdown Output (`preflight_checklist.md`)

```markdown
# Pre-Flight Checklist Results

**Report:** `findings.json`
**Timestamp:** 2026-01-29T11:29:47Z
**User:** waseem.ahmed
**Status:** ✅ PASSED

## Automated Checks

- ✅ **Quality score ≥ 80**
  - Quality score: 85
- ✅ **All findings have file paths**
  - All 3 findings have file paths
...

## Manual Checks

- ✅ Security contact identified?
- ✅ Disclosure method selected?
...
```

## Best Practices

### 1. Always Run Before External Submission

**Never** submit a security report to an external repository without running the pre-flight checklist.

### 2. Use Interactive Mode for Production

Use `--non-interactive` only for CI/CD. For actual submissions, use interactive mode to ensure human review.

### 3. Keep Audit Trail

Always save the `preflight_results.json` and `preflight_checklist.md` files alongside your report for accountability.

### 4. Customize Checklist Per Project

Create project-specific checklists in `.argus/preflight-checklist.yml`:

```yaml
# For HackerOne submissions
manual_checks:
  - "HackerOne program policy reviewed?"
  - "Bounty scope confirmed?"
  - "Duplicate check performed?"
  - "Proof-of-concept sanitized (no real data)?"
```

### 5. Fail Fast on Low Quality

The checker blocks submission immediately if automated checks fail. Fix quality issues before attempting manual review.

## Troubleshooting

### Automated Checks Failing

**Problem:** Quality score too low

```bash
# Run quality validator separately for details
python scripts/report_quality_validator.py findings.json --verbose
```

**Problem:** Missing file paths

```bash
# Check findings manually
jq '.findings[] | select(.file_path == null or .file_path == "unknown")' findings.json
```

**Problem:** Missing line numbers

```bash
# Check findings manually
jq '.findings[] | select(.line_number == null or .line_number < 1)' findings.json
```

### Manual Checks Unclear

**Question:** "90-day timeline agreed?"

- **Answer:** Contact maintainers first, agree on disclosure timeline
- **Default:** 90 days is industry standard (coordinated disclosure)

**Question:** "Report readability tested?"

- **Answer:** Have someone unfamiliar with the code read the report
- **Test:** Can they understand the issue and fix it?

### Custom Checklist Not Loading

```bash
# Verify YAML syntax
python -c "import yaml; yaml.safe_load(open('.argus/preflight-checklist.yml'))"

# Specify checklist explicitly
python scripts/preflight_checker.py --report findings.json --checklist .argus/preflight-checklist.yml
```

## Related Tools

- **`report_quality_validator.py`** - Detailed quality scoring (called by automated checks)
- **`run_ai_audit.py`** - Generates security reports (Phase 1-6)
- **`hybrid_analyzer.py`** - Multi-scanner orchestration

## References

- **SECURITY.md** - Responsible disclosure guidelines
- **CLAUDE.md** - Argus Security 6-phase pipeline
- **Phase 6 Documentation** - External reporting workflow
