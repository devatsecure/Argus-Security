# Phase 2.7 Deep Analysis - GitHub Action Integration Guide

## Overview

Phase 2.7 Deep Analysis enhances Argus Security with advanced semantic vulnerability detection and comprehensive code analysis. This guide explains how to integrate Phase 2.7 capabilities into your GitHub Actions workflows.

## What is Phase 2.7?

Phase 2.7 adds three analysis modes beyond standard scanning:

| Mode | Description | Cost | Use Case |
|------|-------------|------|----------|
| **off** | Standard scanning only (no deep analysis) | Low | Basic security checks |
| **semantic-only** | Semantic vulnerability detection | Medium | PR reviews, quick checks |
| **conservative** | Balanced approach with cost controls | Medium-High | Regular security audits |
| **full** | Comprehensive analysis with maximum coverage | High | Weekly/monthly deep scans |

## GitHub Action Configuration

### Input Parameters

#### Phase 2.7 Specific Parameters

```yaml
inputs:
  deep-analysis-mode:
    description: 'Phase 2.7 Deep Analysis mode (off, semantic-only, conservative, full)'
    required: false
    default: 'off'

  max-files-deep-analysis:
    description: 'Maximum files for Phase 2.7 Deep Analysis'
    required: false
    default: '50'

  deep-analysis-cost-ceiling:
    description: 'Cost ceiling in USD for Phase 2.7'
    required: false
    default: '5.0'

  deep-analysis-timeout:
    description: 'Timeout in seconds for Phase 2.7'
    required: false
    default: '300'

  benchmark:
    description: 'Enable benchmark reporting'
    required: false
    default: 'false'
```

### Quick Start Examples

#### Example 1: Basic PR Review with Semantic Analysis

```yaml
name: PR Security Review
on: [pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: devatsecure/Argus-Security@main
        with:
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
          review-type: security
          deep-analysis-mode: semantic-only
          only-changed: true
          fail-on-blockers: true
```

#### Example 2: Main Branch Conservative Analysis

```yaml
name: Main Branch Security
on:
  push:
    branches: [main]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: devatsecure/Argus-Security@main
        with:
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
          review-type: security
          deep-analysis-mode: conservative
          max-files-deep-analysis: 50
          deep-analysis-cost-ceiling: 5.0
          benchmark: true
```

#### Example 3: Weekly Full Deep Analysis

```yaml
name: Weekly Security Audit
on:
  schedule:
    - cron: '0 2 * * 0'  # Sundays at 2 AM

jobs:
  full-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: devatsecure/Argus-Security@main
        with:
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
          review-type: security
          deep-analysis-mode: full
          max-files-deep-analysis: 200
          deep-analysis-cost-ceiling: 15.0
          deep-analysis-timeout: 900
          benchmark: true
          enable-multi-agent: true
          enable-spontaneous-discovery: true
```

## Analysis Modes Deep Dive

### 1. Semantic-Only Mode

**Best for:** Pull request reviews, quick security checks

**Features:**
- Semantic vulnerability detection
- Context-aware analysis
- Fast execution (2-5 minutes)
- Low cost ($0.50-$2.00 per scan)

**Configuration:**
```yaml
deep-analysis-mode: semantic-only
max-files-deep-analysis: 100
deep-analysis-cost-ceiling: 2.0
deep-analysis-timeout: 180
```

**When to use:**
- Every pull request
- Quick security feedback
- CI/CD pipelines with tight time constraints

### 2. Conservative Mode

**Best for:** Regular security audits, main branch protection

**Features:**
- Balanced analysis depth
- Cost-controlled comprehensive checks
- Medium execution time (5-10 minutes)
- Medium cost ($2.00-$5.00 per scan)

**Configuration:**
```yaml
deep-analysis-mode: conservative
max-files-deep-analysis: 50
deep-analysis-cost-ceiling: 5.0
deep-analysis-timeout: 300
```

**When to use:**
- Main branch commits
- Daily/weekly security checks
- Release preparation

### 3. Full Mode

**Best for:** Comprehensive security audits, compliance reporting

**Features:**
- Maximum analysis depth
- All detection capabilities enabled
- Longer execution time (10-30 minutes)
- Higher cost ($5.00-$15.00 per scan)

**Configuration:**
```yaml
deep-analysis-mode: full
max-files-deep-analysis: 200
deep-analysis-cost-ceiling: 15.0
deep-analysis-timeout: 900
```

**When to use:**
- Weekly/monthly security audits
- Pre-release security validation
- Compliance reporting
- Security incident investigation

## Cost Management

### Understanding Costs

Phase 2.7 costs are based on:
1. Number of files analyzed
2. File size and complexity
3. Analysis depth (mode)
4. LLM API usage (Claude/GPT-4)

### Cost Optimization Strategies

#### 1. Use Appropriate Mode for Context

```yaml
# PR reviews - semantic only
on: pull_request
  deep-analysis-mode: semantic-only
  only-changed: true

# Main branch - conservative
on:
  push:
    branches: [main]
  deep-analysis-mode: conservative

# Scheduled audits - full
on:
  schedule:
    - cron: '0 2 * * 0'
  deep-analysis-mode: full
```

#### 2. Set Cost Ceilings

```yaml
# Hard stop at $5
deep-analysis-cost-ceiling: 5.0

# Per-mode recommendations
semantic-only: 2.0-3.0
conservative: 5.0-8.0
full: 10.0-20.0
```

#### 3. Limit File Scope

```yaml
# PRs - analyze changed files only
only-changed: true
max-files-deep-analysis: 100

# Full scans - limit by priority
max-files-deep-analysis: 200
include-paths: 'src/**,lib/**'
exclude-paths: 'tests/**,docs/**'
```

## Benchmark Reporting

Enable benchmarking to track Phase 2.7 performance:

```yaml
benchmark: true
```

**Benchmark Metrics:**
- Analysis duration
- Files analyzed
- Vulnerabilities found
- False positive rate
- Cost breakdown
- Comparison vs baseline (Phase 2.7 off)

**Example Benchmark Output:**
```json
{
  "phase_27_enabled": true,
  "mode": "conservative",
  "duration_seconds": 342,
  "files_analyzed": 48,
  "vulnerabilities_found": 12,
  "false_positives": 1,
  "cost_usd": 4.23,
  "baseline_comparison": {
    "additional_findings": 3,
    "fp_reduction_percent": 67
  }
}
```

## Advanced Workflows

### Multi-Stage Security Pipeline

```yaml
name: Multi-Stage Security
on: [push, pull_request]

jobs:
  # Stage 1: Fast PR checks
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
          fail-on-blockers: true

  # Stage 2: Conservative main branch
  main-check:
    if: github.event_name == 'push' && github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: devatsecure/Argus-Security@main
        with:
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
          deep-analysis-mode: conservative
          benchmark: true

  # Stage 3: Weekly full audit
  weekly-audit:
    if: github.event_name == 'schedule'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: devatsecure/Argus-Security@main
        with:
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
          deep-analysis-mode: full
          benchmark: true
```

### Conditional Analysis Based on Changes

```yaml
name: Smart Security Analysis
on: [pull_request]

jobs:
  detect-scope:
    runs-on: ubuntu-latest
    outputs:
      security-files-changed: ${{ steps.check.outputs.security }}
    steps:
      - uses: actions/checkout@v4
      - id: check
        run: |
          if git diff --name-only origin/main | grep -E '(auth|security|crypto)'; then
            echo "security=true" >> $GITHUB_OUTPUT
          else
            echo "security=false" >> $GITHUB_OUTPUT
          fi

  security-scan:
    needs: detect-scope
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: devatsecure/Argus-Security@main
        with:
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
          # Use full analysis if security files changed
          deep-analysis-mode: ${{ needs.detect-scope.outputs.security-files-changed == 'true' && 'conservative' || 'semantic-only' }}
```

## Troubleshooting

### Common Issues

#### 1. Cost Ceiling Exceeded

**Error:** "Phase 2.7 analysis stopped: cost ceiling of $5.00 exceeded"

**Solution:**
```yaml
# Increase ceiling or reduce scope
deep-analysis-cost-ceiling: 10.0
# OR
max-files-deep-analysis: 30
```

#### 2. Timeout

**Error:** "Phase 2.7 analysis timed out after 300 seconds"

**Solution:**
```yaml
# Increase timeout or reduce scope
deep-analysis-timeout: 600
# OR
max-files-deep-analysis: 30
```

#### 3. API Rate Limits

**Error:** "Anthropic API rate limit exceeded"

**Solution:**
- Use different modes for different workflows
- Implement retry logic with exponential backoff
- Consider upgrading API tier

## Best Practices

### 1. Workflow Design

- **PR Reviews:** Use `semantic-only` mode with `only-changed: true`
- **Main Branch:** Use `conservative` mode for balanced security
- **Scheduled Audits:** Use `full` mode weekly/monthly
- **Release Gates:** Use `conservative` or `full` mode

### 2. Cost Control

- Set appropriate cost ceilings per mode
- Use `only-changed` for PR workflows
- Exclude non-critical paths (tests, docs, vendor)
- Monitor benchmark reports

### 3. Performance Optimization

- Enable parallel scanning where possible
- Use caching for dependencies
- Set reasonable timeouts
- Prioritize critical files

### 4. Security Posture

- Always enable for main/production branches
- Fail fast on blockers in PR reviews
- Track metrics over time
- Review benchmark reports regularly

## Migration Guide

### From Standard Argus to Phase 2.7

**Before:**
```yaml
- uses: devatsecure/Argus-Security@v1
  with:
    anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
    review-type: security
```

**After (Conservative):**
```yaml
- uses: devatsecure/Argus-Security@main
  with:
    anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
    review-type: security
    deep-analysis-mode: conservative
    max-files-deep-analysis: 50
    deep-analysis-cost-ceiling: 5.0
    benchmark: true
```

## Reference

### Complete Example Workflow

See [.github/workflows/argus-phase-27-deep-analysis.yml](../.github/workflows/argus-phase-27-deep-analysis.yml) for a complete example with:
- PR semantic analysis
- Main branch conservative analysis
- Weekly full analysis
- Manual on-demand analysis
- Benchmark comparison

### Related Documentation

- [Main README](../README.md)
- [CLAUDE.md](../CLAUDE.md)
- [QUICKSTART.md](./QUICKSTART.md)
- [MULTI_AGENT_GUIDE.md](./MULTI_AGENT_GUIDE.md)

## Support

For issues or questions:
- GitHub Issues: https://github.com/devatsecure/Argus-Security/issues
- Documentation: https://github.com/devatsecure/Argus-Security/tree/main/docs
