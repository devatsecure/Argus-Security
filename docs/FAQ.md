# Argus: Frequently Asked Questions

## General Questions

### What is Argus?

Argus is a security control plane that orchestrates multiple security scanners (Semgrep, Trivy, TruffleHog, Checkov), applies AI-powered triage to reduce false positives, and enforces policy gates. It can be used as a GitHub Action, CLI tool, or deployed platform.

### Is Argus free?

Yes! Argus is open source (MIT license) and free to use. You can choose from multiple AI providers including Claude (Anthropic), OpenAI, or Ollama for local inference. API costs vary depending on your chosen provider.

### How is this different from GitHub's built-in security features?

| Feature | GitHub Security | Argus |
|---------|----------------|----------|
| **Secret Scanning** | Pattern-based | Pattern + API verification |
| **Dependency Scanning** | Dependabot alerts | Trivy + reachability analysis |
| **Code Scanning** | CodeQL | Semgrep + AI triage |
| **Noise Reduction** | Manual review | 60-70% auto-suppression |
| **Policy Enforcement** | Manual | Automated Rego gates |
| **Fix Suggestions** | Limited | AI-generated remediations |

Argus **complements** GitHub Security (you can use both), but adds AI triage and policy automation.

---

## Setup & Configuration

### Do I need an API key to use Argus?

**Yes, for most providers.** Argus supports multiple AI providers:

- **Claude (Anthropic)**: Requires `ANTHROPIC_API_KEY`
- **OpenAI**: Requires `OPENAI_API_KEY`
- **Ollama**: No API key needed (local inference)

### How do I get started in under 5 minutes?

1. Create `.github/workflows/argus.yml`:
   ```yaml
   name: Security
   on: [pull_request]
   jobs:
     security:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v4
         - uses: devatsecure/Argus-Security@v1
   ```

2. Open a PR → Argus comments with findings

3. Done! 🎉

### What permissions does Argus need?

**Minimum** (read-only audit):
- `contents: read` - to scan code

**Recommended** (for PR comments):
- `contents: read`
- `pull-requests: write` - to comment on PRs

**Optional** (for automated PRs):
- `contents: write` - to create audit PRs

### Can I run Argus locally (not in GitHub Actions)?

Yes! Install locally:

```bash
git clone https://github.com/devatsecure/Argus-Security.git
cd argus-action
pip install -r requirements.txt
python3 scripts/run_ai_audit.py /path/to/your/repo audit
```

See [PLATFORM.md](../PLATFORM.md#usage) for full CLI documentation.

---

## Cost & Performance

### How much does Argus cost to run?

| AI Provider | Cost per Run | Notes |
|-------------|-------------|--------|
| **Claude Sonnet** | $0.20-0.50 | Depends on findings count |
| **OpenAI GPT-4** | $0.30-0.70 | Varies by model and usage |
| **Ollama** | $0.00 | Local inference, no API calls |

**GitHub Actions runner time**: ~3-5 minutes = $0.008-0.013 (on public repos, free)

### How long does a scan take?

| Repository Size | Typical Duration |
|----------------|------------------|
| Small (<1K files) | 1-2 minutes |
| Medium (1K-5K files) | 3-5 minutes |
| Large (5K-20K files) | 5-10 minutes |
| Monorepo (>20K files) | 10-20 minutes |

**Tips to speed up**:
- Use `only-changed: 'true'` for PR scans (only scan changed files)
- Set `max-files: '50'` to limit scope
- Use `exclude-paths` to skip generated code

### Will Argus slow down my PR reviews?

**No!** Argus runs asynchronously. Developers can continue working while the scan completes (~3-5 min).

**With noise reduction**, you get 3-5 actionable findings instead of 50+ raw alerts, which actually **speeds up** overall review time.

### What AI provider should I choose?

| Aspect | Ollama | Claude Sonnet | OpenAI GPT-4 |
|--------|--------|---------------|--------------|
| **Cost** | $0 (local) | ~$0.35/run | ~$0.50/run |
| **Speed** | 2-3 minutes | 1-2 minutes | 1-2 minutes |
| **Accuracy** | Good | Excellent | Excellent |
| **Setup** | Self-hosted required | API key only | API key only |
| **Best For** | Air-gapped environments, cost-conscious | High-security, general use | Alternative to Claude |

**Recommendation**: Use Claude or OpenAI for best results, Ollama for cost-sensitive or air-gapped environments.

---

## Security & Privacy

### What data does Argus send externally?

| Mode | Data Sent | Recipient |
|------|-----------|-----------|
| **Ollama** | ❌ Nothing | Local inference only |
| **Claude** | ✅ Code snippets (findings context, ~200 lines max) | Anthropic API |
| **OpenAI** | ✅ Code snippets (findings context, ~200 lines max) | OpenAI API |

**Never sent**: Full repository, commit history, secrets, credentials.

### Does Argus store my data?

**No.** Argus is stateless. All processing happens in your GitHub Actions runner and artifacts are stored in GitHub (controlled by you).

**Optional**: You can deploy Argus with PostgreSQL for historical analysis (self-hosted, you control the data).

### Is Argus safe to use on private repositories?

**Yes!** Argus is designed for enterprise use:
- ✅ Open source (audit the code yourself)
- ✅ No telemetry or phone-home
- ✅ No credential storage
- ✅ Runs entirely in your infrastructure
- ✅ Optional: Use Ollama for local inference (no external API calls)

### Can I run Argus in air-gapped environments?

**Yes, with Ollama:**
1. Install Ollama locally
2. Download your chosen model (e.g., llama3, mistral)
3. Configure Argus to use Ollama endpoint
4. Run Argus (no internet required)

**No** with Claude or OpenAI (requires external API access).

---

## Findings & Triage

### Why are some findings suppressed?

Argus auto-suppresses findings with high "noise scores" (>0.7 by default):

**Common suppression reasons**:
- Test files (`test/`, `spec/`, `__tests__/`)
- Documentation (`docs/`, `README.md`)
- Example/template files (`.example`, `sample_`)
- Unverified secrets (pattern match only, no API validation)
- Low-severity findings in non-production code

**You control this**: Adjust `NOISE_THRESHOLD` in your workflow or edit Rego policies.

### How do I suppress a false positive?

**Option 1: React to PR comment**  
React with 👎 and comment why. Argus learns from feedback.

**Option 2: Add to allowlist**  
Create `.argus/allowlist.yml`:
```yaml
suppressions:
  - fingerprint: "abc123def456"  # From finding metadata
    reason: "False positive: test fixture"
    expires: "2025-12-31"
```

**Option 3: Custom Rego policy**  
Edit `policy/rego/pr.rego` to add suppression logic.

### What's the difference between "suppressed" and "ignored"?

- **Suppressed**: Finding is detected but auto-filtered (shown in "Suppressed" section of report)
- **Ignored**: Finding is never detected (via `exclude-paths` or tool config)

**Best practice**: Use suppression (shows why it's not actionable) rather than ignoring (hides it entirely).

### Can I customize what blocks a PR?

**Yes!** Edit `policy/rego/pr.rego`:

```rego
# Default: block on verified secrets + critical CVEs
block if {
    input.findings[_].severity == "critical"
    input.findings[_].verified == true
}

# Custom: also block on high SAST with exploitability "trivial"
block if {
    input.findings[_].severity == "high"
    input.findings[_].category == "SAST"
    input.findings[_].exploitability == "trivial"
}
```

Or use `fail-on` for simpler cases:
```yaml
with:
  fail-on: 'security:critical,security:high'
```

---

## Scanners & Tools

### Which security scanners does Argus use?

| Scanner | Purpose | Enabled by Default |
|---------|---------|-------------------|
| **Semgrep** | SAST (2000+ rules) | ✅ Yes |
| **Trivy** | CVE scanning | ✅ Yes |
| **TruffleHog** | Verified secret detection | ✅ Yes |
| **Checkov** | IaC security | ✅ Yes |
| **Syft** | SBOM generation | ⚙️ On-demand |
| **Cosign** | Artifact signing | ⚙️ On-demand |

### Can I disable specific scanners?

**Yes!** Use scanner-specific flags:

```yaml
with:
  semgrep-enabled: 'false'  # Disable Semgrep
  # Note: Core scanners (TruffleHog, Trivy, Semgrep) are enabled by default
```

Or use `exclude-paths` to skip scanning certain directories:
```yaml
with:
  exclude-paths: 'vendor/**,node_modules/**'
```

### How do I add custom Semgrep rules?

Create `.semgrep/rules.yml` in your repo:

```yaml
rules:
  - id: custom-sql-injection
    pattern: |
      db.query($QUERY)
    message: "Potential SQL injection"
    severity: ERROR
    languages: [javascript, typescript]
```

Argus will automatically use your custom rules alongside the default `p/security-audit` ruleset.

### Does Argus support language X?

**Yes, for most languages:**

| Language | Semgrep | Trivy | TruffleHog | Checkov |
|----------|---------|-------|------------|---------|
| JavaScript/TypeScript | ✅ | ✅ | ✅ | ✅ |
| Python | ✅ | ✅ | ✅ | ✅ |
| Java | ✅ | ✅ | ✅ | ✅ |
| Go | ✅ | ✅ | ✅ | ✅ |
| Ruby | ✅ | ✅ | ✅ | ✅ |
| PHP | ✅ | ✅ | ✅ | ⚠️ |
| C/C++ | ⚠️ | ✅ | ✅ | ❌ |
| Rust | ⚠️ | ✅ | ✅ | ❌ |
| Terraform/IaC | ✅ | ✅ | ✅ | ✅ |

**Legend**: ✅ Full support, ⚠️ Partial support, ❌ Not supported

---

## Troubleshooting

### "AI provider connection failed"

**Cause**: Invalid API key or network issues

**Solutions**:
1. **Check API key**: Verify `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` is set correctly
2. **Test API access**: Ensure your GitHub Actions runner can reach the AI provider API
3. **Try alternative provider**: Switch between Claude, OpenAI, or Ollama
4. **Check rate limits**: Ensure you haven't exceeded API rate limits

### "Cost limit exceeded"

**Cause**: Large repo or many findings triggered excessive API calls

**Solutions**:
1. **Use Ollama**: `with: { ai-provider: 'ollama' }` (free, local)
2. **Increase limit**: `with: { cost-limit: '2.0' }`
3. **Scan fewer files**: `with: { max-files: '50', only-changed: 'true' }`

### "No blockers found but PR still fails"

**Cause**: Custom Rego policy or `fail-on` configuration

**Solutions**:
1. Check Rego policies in `policy/rego/pr.rego`
2. Check `fail-on` setting in workflow
3. Set `fail-on-blockers: 'false'` to disable blocking

### "Argus is too slow"

**Optimizations**:
```yaml
with:
  only-changed: 'true'      # Only scan changed files (PRs)
  max-files: '50'            # Limit file count
  max-file-size: '50000'     # Skip large files (bytes)
  exclude-paths: 'vendor/**,node_modules/**'  # Skip dependencies
```

**Expected speedup**: 2-5x faster on large repos

### "Too many false positives"

**Adjustments**:
```yaml
env:
  NOISE_THRESHOLD: '0.6'     # Lower threshold = more suppression (default: 0.7)
```

Or create `.argus/allowlist.yml` to suppress specific patterns.

### "Important finding was suppressed"

**Review suppression reasons** in the report, then:

1. **If legitimately wrong**: React with 👎 on PR comment (teaches model)
2. **If test file but real risk**: Move to production code or adjust policy
3. **If need manual override**: Lower noise threshold: `NOISE_THRESHOLD: '0.8'`

### Does Argus support caching?

**Yes!** Argus supports multiple caching strategies:

1. **Scanner tool caching**: GitHub Actions automatically caches downloaded scanner binaries
2. **Dependency caching**: Cache node_modules, pip packages, etc. to speed up scans
3. **AI model caching**: When using Ollama, models are cached locally after first download

**Example caching configuration**:
```yaml
- uses: actions/cache@v4
  with:
    path: |
      ~/.cache/semgrep
      ~/.cache/trivy
    key: scanner-cache-${{ runner.os }}
```

### Does Argus show progress during scans?

**Yes!** Argus displays real-time progress:

- Scanner execution status (running, completed, failed)
- File analysis progress (X of Y files analyzed)
- Cost tracking (current spend vs. limit)
- Time elapsed and estimated completion

Progress is shown in GitHub Actions logs and can be monitored in real-time during workflow execution.

---

## Advanced Usage

### Can I run Argus on multiple repositories?

**Yes!** Use the multi-repo coordinator:

```bash
python3 scripts/multi_repo_coordinator.py \
  --config config/repos.json \
  --max-concurrent 3
```

Or create a GitHub Actions matrix:
```yaml
strategy:
  matrix:
    repo: [repo1, repo2, repo3]
steps:
  - uses: actions/checkout@v4
    with:
      repository: ${{ matrix.repo }}
  - uses: devatsecure/Argus-Security@v1
```

### Can I integrate Argus with Slack/Teams/etc?

**Yes!** Argus outputs JSON/SARIF that you can parse:

```yaml
- name: Notify Slack
  if: steps.security.outputs.blockers > 0
  run: |
    curl -X POST $SLACK_WEBHOOK \
      -d "{\"text\": \"🚨 ${{ steps.security.outputs.blockers }} security issues found\"}"
```

Or use `.argus/notifications.yml` (coming soon).

### Can I use Argus in pre-commit hooks?

**Yes!** But not recommended (too slow for pre-commit).

**Better approach**: Use Argus in CI/CD, and use faster tools locally:
- `pre-commit` with `gitleaks` for secrets
- `eslint` for JS linting
- Argus for comprehensive PR review

### How do I generate SBOMs?

**In GitHub Action**:
```yaml
with:
  review-type: 'audit'
  # SBOM automatically generated
```

**Standalone**:
```bash
python3 scripts/sbom_generator.py \
  --repo-path /path/to/repo \
  --output sbom.json
```

**Sign SBOM**:
```bash
cosign sign-blob --key cosign.key sbom.json
```

See [PLATFORM.md#sbom](../PLATFORM.md#sbom-generation-and-signing) for details.

### Can I use custom AI models?

**Yes!** Argus supports:
- **Claude** (Anthropic API)
- **OpenAI** (GPT-4)
- **Ollama** (self-hosted, local)

Example with Ollama:
```yaml
with:
  ai-provider: 'ollama'
  ollama-endpoint: 'http://localhost:11434'
  model: 'llama3:70b'
```

---

## Compliance & Enterprise

### Does Argus help with SOC 2 compliance?

**Yes!** Argus includes a SOC 2 compliance pack:

- **CC6.1**: Access controls (no verified secrets)
- **CC6.6**: Encryption + SBOM requirements
- **CC7.2**: Vulnerability remediation SLA
- **CC7.3**: Incident response timeliness

Enable via:
```bash
opa eval -d policy/rego/compliance_soc2.rego \
  -i findings.json \
  "data.compliance.soc2.decision"
```

See [PLATFORM.md#soc2](../PLATFORM.md#soc-2-compliance-pack) for full documentation.

### Can I use Argus for PCI-DSS compliance?

**Partially.** Argus addresses:
- ✅ PCI-DSS 6.2: Patch vulnerabilities
- ✅ PCI-DSS 6.3: Secure development practices
- ✅ PCI-DSS 6.5: Common vulnerabilities (OWASP Top 10)
- ✅ PCI-DSS 8.2: No hardcoded credentials

But Argus alone doesn't cover full PCI-DSS (network security, physical access, etc.).

### Can I get a report for auditors?

**Yes!** Argus generates:
- **Markdown reports**: Human-readable for auditors
- **JSON**: Structured data for compliance tools
- **SARIF**: Standard format for security tools

Example audit workflow:
```yaml
- uses: devatsecure/Argus-Security@v1
  with:
    review-type: 'audit'
- uses: actions/upload-artifact@v4
  with:
    name: audit-report-${{ github.run_id }}
    path: .argus/reviews/
    retention-days: 365  # Keep for audit trail
```

### Does Argus support role-based access control (RBAC)?

**Not directly.** Argus inherits GitHub's RBAC:
- Who can trigger workflows (GitHub permissions)
- Who can view artifacts (GitHub permissions)
- Who can approve PRs (GitHub branch protection)

For enterprise deployments, see [PLATFORM.md#rbac](../PLATFORM.md#deployment) for custom RBAC.

---

## Comparison Questions

### Argus vs Snyk?

| Feature | Snyk | Argus |
|---------|------|----------|
| **Focus** | Dependency vulnerabilities | Multi-scanner (secrets, SAST, CVE, IaC) |
| **Pricing** | $0-$2,000+/month | Free (open source) |
| **AI Triage** | Limited | ✅ ML-powered (60-70% noise reduction) |
| **Policy Engine** | Yes (cloud) | ✅ Rego (self-hosted) |
| **SBOM** | Yes | ✅ Yes |
| **Self-Hosted** | Limited | ✅ Full control |

**Use both?** Yes! Snyk for dependency monitoring, Argus for PR gates + AI triage.

### Argus vs SonarQube?

| Feature | SonarQube | Argus |
|---------|-----------|----------|
| **Focus** | Code quality + security | Security-first |
| **Deployment** | Self-hosted server | GitHub Action or self-hosted |
| **AI Triage** | No | ✅ Yes |
| **Secret Scanning** | Basic | ✅ Verified (API validation) |
| **Cost** | Free Community, $150+/month Enterprise | Free (open source) |

**Use both?** Yes! SonarQube for ongoing quality, Argus for PR security gates.

### Argus vs GitHub Advanced Security?

| Feature | GitHub Advanced Security | Argus |
|---------|-------------------------|----------|
| **Secret Scanning** | Pattern-based | ✅ Pattern + API verification |
| **Code Scanning** | CodeQL | ✅ Semgrep + AI triage |
| **Dependency Review** | Dependabot | ✅ Trivy + reachability |
| **Noise Reduction** | Manual | ✅ 60-70% auto-suppression |
| **Cost** | $49/user/month | Free |

**Use both?** Absolutely! They complement each other.

---

## Contributing & Support

### How do I report a bug?

1. Check [existing issues](https://github.com/devatsecure/Argus-Security/issues)
2. If new, [open an issue](https://github.com/devatsecure/Argus-Security/issues/new) with:
   - Steps to reproduce
   - Expected vs actual behavior
   - Workflow file (sanitized)
   - Argus version

### How do I request a feature?

1. Check [discussions](https://github.com/devatsecure/Argus-Security/discussions)
2. If new, start a discussion with:
   - Use case / problem
   - Proposed solution
   - Why it's valuable

### How do I contribute code?

See [CONTRIBUTING.md](../CONTRIBUTING.md) for:
- Development setup
- Testing requirements
- Pull request process
- Code style guide

### Is there enterprise support?

**Community support**: Free via GitHub Issues/Discussions

**Enterprise support**: [Contact us](mailto:enterprise@argus.io) for:
- SLA-backed support
- Custom integrations
- Professional services
- Dedicated Slack channel

---

## Still Have Questions?

- 📖 **Documentation**: [PLATFORM.md](../PLATFORM.md)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/devatsecure/Argus-Security/discussions)
- 🐛 **Issues**: [GitHub Issues](https://github.com/devatsecure/Argus-Security/issues)
- 📧 **Email**: support@argus.io

---

*Last updated: November 2025*  
*Argus Version: v1.0.0*
