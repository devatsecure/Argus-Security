# Phase 2.7 Deep Analysis - Quick Reference Card

## 🚀 Quick Start

Copy-paste ready examples for immediate use.

### PR Reviews (Fast & Cheap)

```yaml
- uses: devatsecure/Argus-Security@main
  with:
    anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
    review-type: security
    deep-analysis-mode: semantic-only
    only-changed: true
```

### Main Branch (Balanced)

```yaml
- uses: devatsecure/Argus-Security@main
  with:
    anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
    review-type: security
    deep-analysis-mode: conservative
    benchmark: true
```

### Weekly Audit (Comprehensive)

```yaml
- uses: devatsecure/Argus-Security@main
  with:
    anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
    review-type: security
    deep-analysis-mode: full
    max-files-deep-analysis: 200
    deep-analysis-cost-ceiling: 15.0
```

## 📊 Mode Comparison

| Mode | Cost | Duration | Files | Best For |
|------|------|----------|-------|----------|
| `off` | $0.20 | 1-2 min | Unlimited | Basic scanning |
| `semantic-only` | $0.50-$2 | 2-5 min | 50-100 | PR reviews |
| `conservative` | $2-$5 | 5-10 min | 30-50 | Main branch |
| `full` | $5-$15 | 10-30 min | 100-200 | Weekly audits |

## ⚙️ All Parameters

```yaml
deep-analysis-mode: 'off'           # off, semantic-only, conservative, full
max-files-deep-analysis: '50'       # Max files to analyze
deep-analysis-cost-ceiling: '5.0'   # USD limit
deep-analysis-timeout: '300'        # Seconds
benchmark: 'false'                  # Enable reporting
```

## 💡 Common Patterns

### Pattern 1: Smart PR Workflow

```yaml
name: Smart PR Security
on: [pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: devatsecure/Argus-Security@main
        with:
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
          deep-analysis-mode: semantic-only
          only-changed: true
          fail-on-blockers: true
          comment-on-pr: true
```

### Pattern 2: Multi-Stage Pipeline

```yaml
name: Multi-Stage Security
on: [push, pull_request]

jobs:
  pr-check:
    if: github.event_name == 'pull_request'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: devatsecure/Argus-Security@main
        with:
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
          deep-analysis-mode: semantic-only
          only-changed: true

  main-check:
    if: github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: devatsecure/Argus-Security@main
        with:
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
          deep-analysis-mode: conservative
```

### Pattern 3: Scheduled Deep Scan

```yaml
name: Weekly Security Audit
on:
  schedule:
    - cron: '0 2 * * 0'  # Sundays at 2 AM

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: devatsecure/Argus-Security@main
        with:
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
          deep-analysis-mode: full
          max-files-deep-analysis: 200
          deep-analysis-cost-ceiling: 15.0
          benchmark: true
```

## 🎯 Decision Tree

```
Is this a PR?
├─ Yes → Use semantic-only mode
│         + only-changed: true
│         + fail-on-blockers: true
│
└─ No → Is it main branch?
        ├─ Yes → Use conservative mode
        │         + benchmark: true
        │
        └─ No → Is it scheduled?
                ├─ Yes → Use full mode
                │         + max-files: 200
                │         + cost-ceiling: 15.0
                │
                └─ No → Use off mode
```

## 💰 Cost Optimization

### Technique 1: Only Changed Files

```yaml
only-changed: true                  # PRs only
max-files-deep-analysis: 100
```

### Technique 2: Cost Ceilings

```yaml
# Per-mode recommendations
semantic-only: 2.0
conservative: 5.0
full: 15.0
```

### Technique 3: Exclude Paths

```yaml
exclude-paths: 'tests/**,docs/**,vendor/**'
```

### Technique 4: Time-Based Strategy

```yaml
# PR: semantic-only ($0.50-$2)
# Main: conservative ($2-$5)
# Weekly: full ($5-$15)
# = ~$20-50/week for complete coverage
```

## 🐛 Troubleshooting

### Cost Exceeded

```yaml
# Increase ceiling OR reduce files
deep-analysis-cost-ceiling: 10.0
max-files-deep-analysis: 30
```

### Timeout

```yaml
# Increase timeout OR reduce files
deep-analysis-timeout: 600
max-files-deep-analysis: 30
```

### Too Slow

```yaml
# Use faster mode
deep-analysis-mode: semantic-only
only-changed: true
```

## 📚 Full Documentation

- **Complete Guide:** [docs/PHASE_27_DEEP_ANALYSIS.md](../docs/PHASE_27_DEEP_ANALYSIS.md)
- **Examples:** [.github/workflows/](../workflows/)
- **Main README:** [README.md](../../README.md)

## 🔗 Quick Links

- [action.yml](../action.yml) - Action configuration
- [Example Workflows](../workflows/) - Copy-paste workflows
- [Issues](https://github.com/devatsecure/Argus-Security/issues) - Report problems

---

**TIP:** Start with `semantic-only` for PRs, then scale up to `conservative` and `full` as needed.
