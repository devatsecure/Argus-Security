# Pre-Flight Checklist Quick Start

## TL;DR

Before submitting security reports externally, run:

```bash
python scripts/preflight_checker.py --report findings.json
```

Answer "yes" to all questions. If any fail, fix issues before submitting.

---

## 5-Minute Tutorial

### Step 1: Generate Report

```bash
python scripts/run_ai_audit.py --target external-repo
```

Output: `.argus/reviews/results.json`

### Step 2: Run Pre-Flight Checklist

```bash
python scripts/preflight_checker.py --report .argus/reviews/results.json
```

### Step 3: Review Automated Checks

```
✅ PASS - Quality score ≥ 80
✅ PASS - All findings have file paths
✅ PASS - All findings have line numbers
✅ PASS - All findings have valid severity
```

If any **automated check fails**, stop and fix the issues:

```bash
# Get detailed quality report
python scripts/report_quality_validator.py .argus/reviews/results.json --verbose

# Fix issues in your report generation
# Then re-run preflight checker
```

### Step 4: Answer Manual Questions

```
Security contact identified?
  Confirm (yes/no): yes

Disclosure method selected?
  Confirm (yes/no): yes

90-day timeline agreed with maintainers?
  Confirm (yes/no): yes

Human reviewed report for quality and accuracy?
  Confirm (yes/no): yes

Test report readability?
  Confirm (yes/no): yes

Confirmed this is NOT a public security disclosure?
  Confirm (yes/no): yes
```

**All answers must be "yes"** for approval.

### Step 5: Check Results

```
======================================================================
✅ PRE-FLIGHT CHECKLIST PASSED
======================================================================
Report is approved for external submission.

Checklist results saved to: results_preflight_results.json
Markdown checklist saved to: results_preflight_checklist.md
```

### Step 6: Submit Report

Now you can safely submit to:
- Security email (from SECURITY.md)
- GitHub Security Advisory
- HackerOne / Bugcrowd
- Private vulnerability disclosure program

---

## Common Scenarios

### Scenario 1: CI/CD Pipeline (Non-Interactive)

```yaml
# .github/workflows/security-scan.yml
- name: Generate Report
  run: python scripts/run_ai_audit.py --target ${{ github.event.repository.name }}

- name: Pre-Flight Check (Automated Only)
  run: python scripts/preflight_checker.py --report results.json --non-interactive

- name: Upload Approved Report
  if: success()
  uses: actions/upload-artifact@v3
  with:
    name: approved-security-report
    path: results.json
```

### Scenario 2: Manual External Submission

```bash
# 1. Generate report
python scripts/run_ai_audit.py --target kubernetes/kubernetes

# 2. Pre-flight check (interactive)
python scripts/preflight_checker.py --report results.json

# 3. If approved, submit via Kubernetes security process
# https://kubernetes.io/docs/reference/issues-security/security/
```

### Scenario 3: Custom Checklist for Bug Bounty

```bash
# 1. Create custom checklist
cat > .argus/bugbounty-checklist.yml <<EOF
automated_checks:
  - name: "Quality score ≥ 90"
    validator: "quality_score_validator"

manual_checks:
  - "HackerOne program rules reviewed?"
  - "Impact proof-of-concept included?"
  - "Duplicate check performed?"
  - "Assets in scope verified?"
EOF

# 2. Run with custom checklist
python scripts/preflight_checker.py \
  --report findings.json \
  --checklist .argus/bugbounty-checklist.yml
```

---

## Checklist Decision Tree

```
┌─────────────────────────────────┐
│  Do you have a security report  │
│  to submit externally?           │
└────────────┬────────────────────┘
             │ YES
             ▼
┌─────────────────────────────────┐
│  Run preflight_checker.py       │
└────────────┬────────────────────┘
             │
             ▼
┌─────────────────────────────────┐
│  Automated checks pass?          │
└────────┬────────────────┬───────┘
         │ YES            │ NO
         │                │
         │                ▼
         │    ┌────────────────────────┐
         │    │ Fix quality issues:     │
         │    │ • Add file paths        │
         │    │ • Add line numbers      │
         │    │ • Improve descriptions  │
         │    └──────────┬──────────────┘
         │               │
         │               └─────────────┐
         │                             │
         ▼                             │
┌─────────────────────────────────┐   │
│  Manual checks confirmed?        │   │
└────────┬────────────────┬───────┘   │
         │ YES            │ NO         │
         │                │            │
         │                ▼            │
         │    ┌────────────────────┐  │
         │    │ Address concerns:  │  │
         │    │ • Contact project  │  │
         │    │ • Get timeline OK  │  │
         │    │ • Human review     │  │
         │    └──────────┬─────────┘  │
         │               │             │
         │               └──────────┐  │
         ▼                          │  │
┌─────────────────────────────────┐│  │
│  ✅ APPROVED                     ││  │
│  Submit report externally        ││  │
└─────────────────────────────────┘│  │
                                    │  │
                                    ▼  ▼
                        ┌──────────────────────┐
                        │  🔄 Re-run checker    │
                        └──────────────────────┘
```

---

## FAQ

### Q: Why do I need this?

**A:** Prevents embarrassing low-quality reports with missing file paths, no line numbers, or false positives.

### Q: Can I skip manual checks in CI?

**A:** Yes, use `--non-interactive` flag. But **never** skip for actual external submissions.

### Q: What if automated checks fail?

**A:** Fix the quality issues first:

```bash
# See detailed report
python scripts/report_quality_validator.py findings.json --verbose

# Common fixes:
# - Ensure all findings have file_path set
# - Ensure all findings have line_number >= 1
# - Improve finding descriptions (>= 50 chars)
# - Set severity for all findings
```

### Q: Can I customize the checklist?

**A:** Yes! Edit `.argus/preflight-checklist.yml` or create a custom one:

```bash
python scripts/preflight_checker.py --report findings.json --checklist custom.yml
```

### Q: What happens if I say "no" to a manual check?

**A:** The checker fails and blocks submission. You must answer "yes" to all checks.

### Q: Where are the results saved?

**A:** Two files are created:
- `{report}_preflight_results.json` - Machine-readable audit trail
- `{report}_preflight_checklist.md` - Human-readable summary

### Q: Can I bypass the checker?

**A:** Technically yes, but **don't**. You risk:
- Submitting low-quality reports
- Damaging your/your org's reputation
- Getting blocked from disclosure programs
- Wasting maintainers' time

---

## One-Liners

```bash
# Basic check
python scripts/preflight_checker.py --report findings.json

# Non-interactive (CI)
python scripts/preflight_checker.py --report findings.json --non-interactive

# Custom checklist
python scripts/preflight_checker.py --report findings.json --checklist custom.yml

# Check quality only
python scripts/report_quality_validator.py findings.json

# Verbose quality check
python scripts/report_quality_validator.py findings.json --verbose
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | ✅ All checks passed - approved for submission |
| 1 | ❌ Checks failed - NOT approved |

Use in scripts:

```bash
if python scripts/preflight_checker.py --report findings.json; then
    echo "Approved! Submitting..."
    ./submit_report.sh findings.json
else
    echo "Failed pre-flight checks. Fix issues and try again."
    exit 1
fi
```

---

## Need Help?

- **Full docs:** `docs/PREFLIGHT_CHECKLIST.md`
- **Quality validator:** `python scripts/report_quality_validator.py --help`
- **Pre-flight checker:** `python scripts/preflight_checker.py --help`
- **Checklist config:** `.argus/preflight-checklist.yml`
