# Lite Mode Profile

**Fast, focused security and quality scans for rapid feedback.**

## Overview

Lite Mode uses only 3 specialized agents instead of the full 22-agent suite:
- **Security Agent** - Critical vulnerabilities only
- **Quality Agent** - High-impact bugs only  
- **Performance Agent** - Critical bottlenecks only

## When to Use Lite Mode

✅ **Use Lite Mode for:**
- Pull request reviews (fast feedback)
- Pre-commit hooks (don't slow down devs)
- Exploratory scans (quick overview)
- Budget-constrained projects (<$0.25 per scan)
- Learning/trying Argus

❌ **Use Full Mode for:**
- Production deployments
- Security audits
- Comprehensive reviews
- Compliance requirements

## Performance Comparison

| Metric | Lite Mode | Full Mode |
|--------|-----------|-----------|
| **Agents** | 3 | 22 |
| **Scan Time** | 1-2 minutes | 4-5 minutes |
| **Cost** | $0.10-0.25 | $0.35-1.00 |
| **Findings** | 5-15 (critical only) | 20-50 (all severities) |
| **False Positives** | ~10% | ~5% |

## Usage

### Docker
```bash
docker run --rm \
  -v $(pwd):/workspace \
  -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
  -e AGENT_PROFILE=lite \
  ghcr.io/devatsecure/argus-action:latest \
  /workspace audit
```

### GitHub Actions
```yaml
- uses: devatsecure/argus-action@v1
  with:
    anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
    agent_profile: lite
    multi_agent_mode: sequential  # Lite mode uses sequential
```

### CLI
```bash
export AGENT_PROFILE=lite
python scripts/run_ai_audit.py /path/to/repo audit
```

## What You Get

### Output Files
```
.argus/reviews/
├── audit-report.md          # Human-readable findings
├── security-findings.json   # Machine-readable
├── results.sarif           # GitHub Security integration
└── metrics.json            # Performance metrics
```

### Sample Report
```markdown
## 🔍 Lite Mode Scan Results

**Scan Time:** 1.2 minutes
**Cost:** $0.18
**Files Analyzed:** 45

### Critical Findings (3)

1. **SQL Injection in user_controller.py**
   - Line: 67
   - Fix: Use parameterized queries
   
2. **Unhandled exception in payment.py**
   - Line: 123
   - Fix: Add try-except with rollback

3. **N+1 query in users/list.py**
   - Line: 89
   - Fix: Use select_related()

### High Priority (2)

4. **Missing input validation**
   - File: api/endpoints.py:45
   
5. **Race condition in cache**
   - File: utils/cache.py:78
```

## Upgrading to Full Mode

When you need comprehensive analysis:

```yaml
# Change from:
agent_profile: lite

# To:
agent_profile: default
multi_agent_mode: parallel  # Or sequential
```

## Configuration

Create `.argus.yml`:

```yaml
# Use lite mode
agent_profile: lite

# Lite-specific settings
lite_mode:
  max_findings_per_agent: 10
  time_per_file_seconds: 30
  skip_low_priority: true
  skip_medium_priority: true
  
# Still respect cost limits
cost_limit: 0.25
max_files: 50
```

## Lite Mode Philosophy

**"Find the critical issues fast, skip the noise."**

- Focus on exploitable vulnerabilities
- Report bugs that cause failures
- Identify performance killers
- Skip style and minor issues
- Deliver results in <2 minutes

## Feedback

Lite mode too fast and missing issues? Try:
```yaml
agent_profile: default
multi_agent_mode: sequential
```

Lite mode too slow or expensive? Try:
```yaml
cost_limit: 0.15
max_files: 25
```
