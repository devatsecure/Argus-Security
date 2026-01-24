# Argus: Usage Examples & Cookbook

Practical examples for common Argus use cases.

---

## Table of Contents

- [PR Security Gates](#pr-security-gates)
- [Scheduled Audits](#scheduled-audits)
- [Multi-Repository Scanning](#multi-repository-scanning)
- [Custom Policies](#custom-policies)
- [SBOM Generation](#sbom-generation)
- [Integration Examples](#integration-examples)
- [Advanced Workflows](#advanced-workflows)

---

## PR Security Gates

### Basic PR Gate (Block on Critical Issues)

```yaml
name: PR Security Gate
on:
  pull_request:
    branches: [main, develop]

jobs:
  security:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Run Security Scan
        uses: devatsecure/Argus-Security@v1
        with:
          review-type: 'security'
          fail-on-blockers: 'true'
          only-changed: 'true'  # Only scan changed files
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
```

**Use Case**: Block PRs with verified secrets or critical vulnerabilities.

---

### Permissive PR Gate (Comment Only, Don't Block)

```yaml
name: PR Security Scan
on: [pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Security Scan
        uses: devatsecure/Argus-Security@v1
        with:
          fail-on-blockers: 'false'  # Never fail
          comment-on-pr: 'true'       # Just comment
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
```

**Use Case**: Get security feedback without blocking development velocity.

---

### Granular Blocking (Block Only Critical + High)

```yaml
name: PR Security
on: [pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Security Scan
        uses: devatsecure/Argus-Security@v1
        with:
          fail-on: 'security:critical,security:high'
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
```

**Use Case**: Block critical/high, but allow medium/low to merge (address later).

---

### PR Gate with Exploit Analysis (Aardvark Mode)

```yaml
name: PR Security with Exploit Analysis
on: [pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Security Scan
        uses: devatsecure/Argus-Security@v1
        with:
          enable-exploit-analysis: 'true'
          exploitability-threshold: 'moderate'  # Block if moderate or easier
          generate-security-tests: 'true'       # Auto-gen tests for vulns
```

**Use Case**: Block PRs with easily exploitable vulnerabilities + generate PoC tests.

---

## Scheduled Audits

### Weekly Full Audit (Sundays at 2 AM)

```yaml
name: Weekly Security Audit
on:
  schedule:
    - cron: '0 2 * * 0'  # Sundays at 2 AM UTC

jobs:
  audit:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      pull-requests: write
      issues: write
    
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Full history
      
      - name: Full Security Audit
        uses: devatsecure/Argus-Security@v1
        with:
          review-type: 'audit'
          fail-on-blockers: 'false'  # Don't fail, just report
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
      
      - name: Upload Audit Report
        uses: actions/upload-artifact@v4
        with:
          name: security-audit-${{ github.run_id }}
          path: .argus/reviews/
          retention-days: 365  # Keep for compliance
      
      - name: Create Issue if Blockers Found
        if: steps.audit.outputs.blockers > 0
        uses: actions/github-script@v7
        with:
          script: |
            await github.rest.issues.create({
              owner: context.repo.owner,
              repo: context.repo.repo,
              title: '🚨 Weekly Audit: ${{ steps.audit.outputs.blockers }} Critical Issues',
              body: 'See audit report in artifacts: code-review-reports-${{ github.run_id }}',
              labels: ['security', 'audit']
            });
```

**Use Case**: Regular security audits with automated issue tracking.

---

### Daily Dependency Scan

```yaml
name: Daily Dependency Scan
on:
  schedule:
    - cron: '0 9 * * *'  # Daily at 9 AM UTC

jobs:
  dependencies:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Scan Dependencies
        uses: devatsecure/Argus-Security@v1
        with:
          review-type: 'security'
          semgrep-enabled: 'false'  # Skip SAST for speed
          # Focus on Trivy (CVE scanning)
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```

**Use Case**: Monitor for new CVEs in dependencies without full SAST.

---

### Monthly Compliance Report

```yaml
name: Monthly Compliance Report
on:
  schedule:
    - cron: '0 0 1 * *'  # First of month at midnight

jobs:
  compliance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Security Audit
        uses: devatsecure/Argus-Security@v1
        with:
          review-type: 'audit'
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
      
      - name: Generate SBOM
        run: |
          python3 scripts/sbom_generator.py \
            --repo-path . \
            --output sbom-$(date +%Y%m).json
      
      - name: Evaluate SOC2 Compliance
        run: |
          opa eval \
            -d policy/rego/compliance_soc2.rego \
            -i .argus/reviews/results.json \
            "data.compliance.soc2.decision" \
            --format pretty > compliance-report.txt
      
      - name: Upload Compliance Package
        uses: actions/upload-artifact@v4
        with:
          name: compliance-${{ github.run_id }}
          path: |
            .argus/reviews/
            sbom-*.json
            compliance-report.txt
          retention-days: 2555  # 7 years for compliance
```

**Use Case**: Monthly compliance reporting for SOC2/PCI-DSS audits.

---

## Multi-Repository Scanning

### Matrix: Scan Multiple Repos

```yaml
name: Multi-Repo Security Scan
on:
  schedule:
    - cron: '0 3 * * 0'  # Weekly

jobs:
  security:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        repo:
          - org/api-service
          - org/web-app
          - org/mobile-backend
          - org/admin-dashboard
    
    steps:
      - uses: actions/checkout@v4
        with:
          repository: ${{ matrix.repo }}
          token: ${{ secrets.PAT_TOKEN }}  # Need PAT for other repos
      
      - name: Scan ${{ matrix.repo }}
        uses: devatsecure/Argus-Security@v1
        with:
          review-type: 'audit'
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
      
      - name: Upload Results
        uses: actions/upload-artifact@v4
        with:
          name: scan-${{ matrix.repo }}-${{ github.run_id }}
          path: .argus/reviews/
```

**Use Case**: Centralized security scanning across multiple repositories.

---

### Monorepo: Scan Multiple Services

```yaml
name: Monorepo Security
on: [pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        service: [api, web, worker, admin]
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Scan ${{ matrix.service }}
        uses: devatsecure/Argus-Security@v1
        with:
          project-path: 'services/${{ matrix.service }}'
          only-changed: 'true'
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
```

**Use Case**: Parallel scanning of monorepo services.

---

## Custom Policies

### Custom Rego Policy: Block Regex DoS

Create `.argus/policy/custom.rego`:

```rego
package custom

# Block on regex DoS vulnerabilities
block_on_regex_dos if {
    some finding in input.findings
    finding.category == "SAST"
    contains(lower(finding.title), "regex")
    contains(lower(finding.title), "dos")
    finding.noise_score < 0.5
}

# Decision
decision := {
    "allow": not block_on_regex_dos,
    "block": block_on_regex_dos,
    "reason": "Regex DoS vulnerability found"
}
```

Workflow:

```yaml
- uses: devatsecure/Argus-Security@v1
  with:
    anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}

- name: Evaluate Custom Policy
  run: |
    opa eval \
      -d .argus/policy/custom.rego \
      -i .argus/reviews/results.json \
      "data.custom.decision" \
      --format pretty
    
    # Fail if blocked
    if [ "$(opa eval -d .argus/policy/custom.rego -i .argus/reviews/results.json 'data.custom.decision.block' --format raw)" = "true" ]; then
      echo "Custom policy blocked this PR"
      exit 1
    fi
```

**Use Case**: Organization-specific security policies.

---

### Block if Coverage Drops

```yaml
name: PR Gate with Coverage
on: [pull_request]

jobs:
  security-and-quality:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      # Run tests + coverage
      - name: Run Tests
        run: |
          pytest --cov=. --cov-report=json
      
      # Security scan
      - name: Security Scan
        uses: devatsecure/Argus-Security@v1
        with:
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
      
      # Combined gate
      - name: Quality Gate
        run: |
          # Fail if coverage < 80%
          COVERAGE=$(jq '.totals.percent_covered' coverage.json)
          if (( $(echo "$COVERAGE < 80" | bc -l) )); then
            echo "Coverage too low: $COVERAGE%"
            exit 1
          fi
          
          # Fail if security blockers
          BLOCKERS="${{ steps.security.outputs.blockers }}"
          if [ "$BLOCKERS" -gt "0" ]; then
            echo "Security blockers found: $BLOCKERS"
            exit 1
          fi
```

**Use Case**: Combined security + quality gates.

---

## SBOM Generation

### Generate SBOM on Release

```yaml
name: Release with SBOM
on:
  release:
    types: [published]

jobs:
  sbom:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      id-token: write  # For signing
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Generate SBOM
        run: |
          python3 scripts/sbom_generator.py \
            --repo-path . \
            --output sbom.json
      
      - name: Sign SBOM
        run: |
          # Install cosign
          curl -sLO https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64
          chmod +x cosign-linux-amd64
          
          # Sign with keyless (OIDC)
          ./cosign-linux-amd64 sign-blob \
            --bundle sbom.bundle.json \
            sbom.json
      
      - name: Upload SBOM to Release
        uses: softprops/action-gh-release@v1
        with:
          files: |
            sbom.json
            sbom.bundle.json
```

**Use Case**: Supply chain transparency with signed SBOMs.

---

### SBOM as PR Artifact

```yaml
- uses: devatsecure/Argus-Security@v1
  with:
    review-type: 'audit'

- name: Generate SBOM
  run: python3 scripts/sbom_generator.py --repo-path . --output sbom.json

- name: Upload SBOM
  uses: actions/upload-artifact@v4
  with:
    name: sbom-${{ github.event.pull_request.number }}
    path: sbom.json
```

**Use Case**: Track dependency changes in PRs.

---

## Integration Examples

### Slack Notification on Critical Findings

```yaml
- name: Security Scan
  id: scan
  uses: devatsecure/Argus-Security@v1
  with:
    anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}

- name: Notify Slack
  if: steps.scan.outputs.blockers > 0
  run: |
    curl -X POST ${{ secrets.SLACK_WEBHOOK }} \
      -H 'Content-Type: application/json' \
      -d '{
        "text": "🚨 *Security Alert*",
        "blocks": [
          {
            "type": "section",
            "text": {
              "type": "mrkdwn",
              "text": "*${{ steps.scan.outputs.blockers }}* critical security issues found in PR #${{ github.event.pull_request.number }}"
            }
          },
          {
            "type": "section",
            "text": {
              "type": "mrkdwn",
              "text": "View: <${{ github.event.pull_request.html_url }}|PR #${{ github.event.pull_request.number }}>"
            }
          }
        ]
      }'
```

**Use Case**: Real-time security alerts to team Slack channel.

---

### Jira Ticket Creation

```yaml
- name: Security Scan
  id: scan
  uses: devatsecure/Argus-Security@v1

- name: Create Jira Ticket
  if: steps.scan.outputs.blockers > 0
  uses: atlassian/gajira-create@v3
  with:
    project: SEC
    issuetype: Bug
    summary: 'Security: ${{ steps.scan.outputs.blockers }} critical issues in ${{ github.repository }}'
    description: |
      Critical security findings from automated scan.
      
      Repository: ${{ github.repository }}
      Branch: ${{ github.ref }}
      Commit: ${{ github.sha }}
      
      Blockers: ${{ steps.scan.outputs.blockers }}
      Suggestions: ${{ steps.scan.outputs.suggestions }}
      
      View full report: ${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}
```

**Use Case**: Automatic security ticket creation in Jira.

---

### PagerDuty Alert on Production Secrets

```yaml
- name: Security Scan
  id: scan
  uses: devatsecure/Argus-Security@v1

- name: Check for Verified Secrets
  id: check-secrets
  run: |
    VERIFIED=$(jq '[.findings[] | select(.category == "secret" and .verified == true)] | length' .argus/reviews/results.json)
    echo "verified=$VERIFIED" >> $GITHUB_OUTPUT

- name: PagerDuty Alert
  if: steps.check-secrets.outputs.verified > 0
  run: |
    curl -X POST https://api.pagerduty.com/incidents \
      -H 'Authorization: Token token=${{ secrets.PAGERDUTY_TOKEN }}' \
      -H 'Content-Type: application/json' \
      -d '{
        "incident": {
          "type": "incident",
          "title": "🚨 CRITICAL: Verified secrets in ${{ github.repository }}",
          "service": {
            "id": "${{ secrets.PAGERDUTY_SERVICE_ID }}",
            "type": "service_reference"
          },
          "urgency": "high",
          "body": {
            "type": "incident_body",
            "details": "${{ steps.check-secrets.outputs.verified }} verified secrets found. Immediate rotation required."
          }
        }
      }'
```

**Use Case**: Page on-call engineer if live secrets are detected.

---

## Advanced Workflows

### Multi-Agent Parallel Analysis

```yaml
name: Advanced Security Scan
on: [pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Multi-Agent Scan
        uses: devatsecure/Argus-Security@v1
        with:
          multi-agent-mode: 'parallel'  # Run specialized agents in parallel
          enable-exploit-analysis: 'true'
          generate-security-tests: 'true'
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
```

**Agents**:
- Security Agent (secrets, CVEs)
- SAST Agent (code patterns)
- IaC Agent (infrastructure)
- Exploit Agent (attack chains)
- Test Generator Agent (security tests)

**Use Case**: Maximum coverage with parallel specialized analysis.

---

### Self-Hosted Runner with GPU (Foundation-Sec)

```yaml
name: Security Scan (GPU-Accelerated)
on: [pull_request]

jobs:
  security:
    runs-on: [self-hosted, linux, gpu]  # GPU runner
    steps:
      - uses: actions/checkout@v4
      
      - name: Security Scan
        uses: devatsecure/Argus-Security@v1
        with:
          foundation-sec-enabled: 'true'
          foundation-sec-device: 'cuda'  # Use GPU
          # 10x faster Foundation-Sec inference
```

**Use Case**: Large repos with self-hosted GPU for faster AI triage.

---

### Progressive Security (Gradually Increase Strictness)

```yaml
name: Progressive Security
on: [pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      # Week 1-2: Comment only, don't block
      - name: Security Scan (Learning Mode)
        if: ${{ env.SECURITY_MODE == 'learning' }}
        uses: devatsecure/Argus-Security@v1
        with:
          fail-on-blockers: 'false'
          comment-on-pr: 'true'
      
      # Week 3-4: Block critical only
      - name: Security Scan (Critical Block)
        if: ${{ env.SECURITY_MODE == 'critical' }}
        uses: devatsecure/Argus-Security@v1
        with:
          fail-on: 'security:critical'
      
      # Week 5+: Block critical + high
      - name: Security Scan (Strict)
        if: ${{ env.SECURITY_MODE == 'strict' }}
        uses: devatsecure/Argus-Security@v1
        with:
          fail-on: 'security:critical,security:high'
```

**Use Case**: Gradual rollout to avoid disrupting existing workflows.

---

### Pre-Release Security Checklist

```yaml
name: Pre-Release Checklist
on:
  pull_request:
    branches: [release/*]

jobs:
  pre-release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      # Full security audit
      - name: Security Audit
        uses: devatsecure/Argus-Security@v1
        with:
          review-type: 'audit'
          fail-on-blockers: 'true'
      
      # Generate SBOM
      - name: Generate SBOM
        run: python3 scripts/sbom_generator.py --repo-path . --output sbom.json
      
      # Sign artifacts
      - name: Sign SBOM
        run: cosign sign-blob --key cosign.key sbom.json
      
      # Verify dependencies
      - name: License Check
        run: |
          # Check for GPL/AGPL licenses
          if grep -r "GPL" sbom.json; then
            echo "GPL license found - requires legal review"
            exit 1
          fi
      
      # All checks pass
      - name: Checklist Complete
        run: echo "✅ Release ready"
```

**Use Case**: Comprehensive security checklist before releases.

---

## Tips & Best Practices

### Cost Optimization

```yaml
# Use Foundation-Sec (free) for PRs
with:
  ai-provider: 'foundation-sec'
  only-changed: 'true'

# Use Claude (paid) for releases
with:
  ai-provider: 'anthropic'
  review-type: 'audit'
```

### Performance Optimization

```yaml
# Scan only relevant files
with:
  max-files: '100'
  exclude-paths: 'vendor/**,node_modules/**,*.min.js'
```

### Gradual Rollout

1. Week 1-2: Comment-only mode, gather feedback
2. Week 3-4: Block on critical only
3. Week 5+: Block on critical + high

### Testing Argus Changes

```yaml
# Test on feature branches before main
on:
  push:
    branches: [test-argus]
```

---

## More Examples

See the `examples/workflows/` directory for:
- `basic-workflow.yml` - Simplest setup
- `advanced-workflow.yml` - Full features
- `hardened-workflow.yml` - Maximum security
- `monorepo-workflow.yml` - Monorepo scanning
- `multi-agent-workflow.yml` - Parallel agents
- `pr-review-mode.yml` - PR-specific config
- `scheduled-audit.yml` - Weekly audits

---

*Need help with your specific use case? [Open a discussion](https://github.com/devatsecure/Argus-Security/discussions)*
