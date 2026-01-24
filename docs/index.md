# Argus Documentation

Welcome to Argus, the most comprehensive open-source AI-powered security platform for code analysis.

---

## 🚀 Getting Started

Start here if you're new to Argus:

- **[Quick Start Guide](../QUICKSTART.md)** - Get up and running in 5 minutes
- **[Installation & Setup](../README.md#installation)** - Detailed installation instructions
- **[Demo & Tutorials](DEMO.md)** - Video tutorials and live demos
- **[First Security Scan](../README.md#quick-start-3-minutes)** - Run your first scan

---

## 📚 Core Documentation

### Features

Learn about Argus capabilities:

- **[Scanner Overview](references/scanner-reference.md)** - All 13 integrated security features
  - TruffleHog - Verified secret detection
  - Gitleaks - Pattern-based secret scanning
  - Semgrep - SAST with 2000+ rules
  - Trivy - CVE and dependency scanning
  - Checkov - Infrastructure-as-Code security
  - API Security - OWASP API Top 10 testing
  - DAST - Dynamic application security testing
  - Supply Chain - Dependency attack detection
  - Fuzzing - AI-guided intelligent fuzzing
  - Threat Intel - Real-time threat context enrichment
  - Remediation - AI-powered fix generation
  - Runtime Security - Container threat monitoring
  - Regression Testing - Automated security regression tests

- **[AI Triage & Noise Reduction](adrs/0003-ai-triage-strategy.md)** - Reduce false positives by 60-70%
  - Claude (Anthropic) integration
  - OpenAI (GPT-4) support
  - Ollama (local LLM) for cost-free scanning

- **[SAST-DAST Correlation](sast-dast-correlation.md)** - AI-powered verification of exploitability
- **[Security Test Generation](security-test-generator.md)** - Auto-generate pytest/Jest tests for vulnerabilities
- **[API Security Testing](DAST_QUICKSTART.md)** - OWASP API Top 10 vulnerability detection
- **[Supply Chain Security](#supply-chain)** - Dependency attack detection and fuzzing
- **[Threat Intelligence](features/threat-intelligence.md)** - Real-time threat context from CVE, CISA KEV, EPSS
- **[Automated Remediation](features/remediation.md)** - AI-generated fix suggestions with code patches
- **[Runtime Security](features/runtime-security.md)** - Container runtime threat monitoring
- **[Regression Testing](features/regression-testing.md)** - Ensure fixed vulnerabilities stay fixed
- **[Intelligent Caching](../README.md#intelligent-caching)** - 10-100x faster repeat scans
- **[Real-Time Progress](../README.md#real-time-progress)** - Beautiful terminal UI with progress bars
- **[Feedback Learning](../README.md#feedback-collection--learning)** - Continuous improvement through user feedback
- **[Observability Dashboard](../README.md#observability-dashboard)** - Real-time visualization of AI decision quality
- **[Plugin Architecture](../README.md#plugin-architecture)** - Load custom scanners without code changes

### Guides

How to use Argus effectively:

- **[Best Practices](best-practices.md)** - Recommended patterns and configurations
- **[Usage Examples](EXAMPLES.md)** - Common use cases and workflows
- **[CI/CD Integration](integration-guide-sast-dast.md)** - GitHub Actions, GitLab CI, Jenkins
- **[Ollama Setup](OLLAMA_SETUP.md)** - Free local LLM for cost-free scanning
- **[Threat Modeling](PYTM_INTEGRATION.md)** - Deterministic STRIDE-based threat analysis
- **[Dual Audit Workflow](DUAL_AUDIT_WORKFLOW.md)** - Multi-agent security analysis
- **[Docker Testing](DOCKER_TESTING_GUIDE.md)** - Container-based testing guide

### Reference

Technical documentation and API reference:

- **[Scanner Reference](references/scanner-reference.md)** - Complete scanner documentation
- **[Configuration Options](../README.md#configuration)** - Environment variables and CLI flags
- **[CLI Reference](../README.md#local-cli-usage)** - All commands and options
- **[Policy Gates](../README.md#policy-gates)** - Rego-based policy enforcement
- **[Metrics Calculator](METRICS_CALCULATOR.md)** - Cost and performance metrics
- **[LLM as Judge](LLM_AS_JUDGE_COMPLIANCE.md)** - Compliance validation framework
- **[Pairwise Comparison](pairwise_comparison_guide.md)** - Scanner comparison methodology

---

## 🏗️ Architecture

Understand how Argus works:

- **[System Overview](architecture/overview.md)** - High-level architecture and data flow
- **[Multi-Scanner Architecture](adrs/0002-multi-scanner-architecture.md)** - Why we use 4+ scanners in parallel
- **[AI Triage Strategy](adrs/0003-ai-triage-strategy.md)** - How we reduce false positives
- **[Agent-Native Features](../README.md#-new-agent-native-features)** - Continuous learning and self-observation

---

## 🔐 Advanced Features

### Supply Chain Security

Protect against dependency attacks:

- **Dependency Attack Detection** - Identify malicious packages and typosquatting
- **Build Poisoning Prevention** - Detect compromised build pipelines
- **Intelligent Fuzzing** - AI-guided fuzzing for custom vulnerabilities
- **SBOM Generation** - Software Bill of Materials creation and signing
- **Provenance Tracking** - Verify artifact origins

**Documentation:** Coming in v1.2.0 - See [Security Features Roadmap](SECURITY_FEATURES_ROADMAP.md)

### API Security Testing

Comprehensive API vulnerability detection:

- **OWASP API Top 10 Coverage:**
  - API1:2023 Broken Object Level Authorization (BOLA/IDOR)
  - API2:2023 Broken Authentication
  - API3:2023 Broken Object Property Level Authorization
  - API4:2023 Unrestricted Resource Consumption
  - API5:2023 Broken Function Level Authorization
  - API6:2023 Unrestricted Access to Sensitive Business Flows
  - API7:2023 Server Side Request Forgery (SSRF)
  - API8:2023 Security Misconfiguration
  - API9:2023 Improper Inventory Management
  - API10:2023 Unsafe Consumption of APIs

- **Endpoint Discovery:** Automatic detection of REST, GraphQL, gRPC endpoints
- **Authentication Testing:** Session fixation, JWT vulnerabilities, OAuth flaws
- **Authorization Testing:** IDOR, privilege escalation, missing access controls

**Quick Start:** [DAST Quick Start Guide](DAST_QUICKSTART.md)

### DAST (Dynamic Application Security Testing)

Runtime vulnerability detection using Nuclei:

- **4000+ Templates:** Pre-built exploits and vulnerability checks
- **Custom Template Support:** Write your own Nuclei templates
- **SAST-DAST Correlation:** AI verifies if static findings are exploitable
- **Severity Filtering:** Critical, High, Medium, Low
- **CI/CD Integration:** Run DAST scans in pipelines

**Documentation:** [SAST-DAST Correlation Guide](sast-dast-correlation.md)

---

## 📖 Use Cases

Real-world scenarios:

### PR Security Gate

Block PRs with verified threats:

```yaml
- uses: devatsecure/Argus-Security@v1
  with:
    anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
    fail-on-blockers: 'true'
    only-changed: 'true'
```

**Benefits:** Prevents vulnerabilities from reaching production

### Scheduled Security Audit

Weekly comprehensive scans:

```yaml
on:
  schedule:
    - cron: '0 2 * * 0'  # Sundays at 2 AM
```

**Benefits:** Catch new CVEs and configuration drift

### Local Development

Fast feedback during development:

```bash
python scripts/run_ai_audit.py --only-changed --max-files 20
```

**Benefits:** Fix security issues before committing

### Compliance Reporting

SOC 2, PCI-DSS audit reports:

```bash
./scripts/argus gate --stage release --sbom-present
```

**Benefits:** Automated compliance validation

---

## 🎯 Performance & Cost

### Benchmarks

| Metric | First Run | Cached Repeat | Speedup |
|--------|-----------|---------------|---------|
| Runtime | 3-5 min | 30-60 sec | 10-100x |
| Cost (Claude) | $0.20-0.50 | $0.00 | N/A |
| Cost (Ollama) | $0.00 | $0.00 | N/A |

### Noise Reduction

| Stage | Findings | Reduction |
|-------|----------|-----------|
| Raw scanners | 147 | - |
| Heuristic filters | 78 | 47% |
| ML noise scoring | 52 | 33% |
| AI triage | 18 | 65% |
| **Total** | **18** | **88%** |

---

## 🛠️ Troubleshooting

### Common Issues

- **[FAQ](FAQ.md)** - Frequently asked questions
- **[GitHub Issues](https://github.com/devatsecure/Argus-Security/issues)** - Known issues and bug reports
- **[GitHub Discussions](https://github.com/devatsecure/Argus-Security/discussions)** - Community Q&A

### Quick Fixes

**"Cost limit exceeded"** → Use Ollama (free) or increase limit
**"Scanner X not found"** → Scanners auto-install on first run
**"Too many false positives"** → Enable AI triage with Claude
**"Argus is too slow"** → Use `--only-changed` and `--max-files 50`

See [README.md Troubleshooting](../README.md#troubleshooting) for more.

---

## 🎓 Learning Resources

### Tutorials

- **[Video Tutorials](DEMO.md)** - Step-by-step video guides
- **[Audit Monitor Guide](audit_monitor_guide.md)** - Continuous monitoring setup
- **[Integration Guide](integration-guide-sast-dast.md)** - SAST+DAST workflow

### Blog Posts & Case Studies

- Reducing False Positives by 60-70% (coming soon)
- How We Built an Agent-Native Security Platform (coming soon)
- Migrating from Manual Security Reviews to Argus (coming soon)

### Community

- **[GitHub Discussions](https://github.com/devatsecure/Argus-Security/discussions)** - Ask questions, share tips
- **[Contributing Guide](../.github/CONTRIBUTING.md)** - How to contribute
- **[Code of Conduct](../.github/CODE_OF_CONDUCT.md)** - Community guidelines

---

## 📋 Roadmap

See what's coming next:

- **[Security Features Roadmap](SECURITY_FEATURES_ROADMAP.md)** - Future security capabilities
- **[Agent-Native Roadmap](AGENT_NATIVE_ROADMAP.md)** - Continuous learning and self-improvement
- **[CHANGELOG](../CHANGELOG.md)** - Version history and releases

**Current Version:** v1.1.0
**Next Release:** v1.2.0 (Q1 2026) - Supply Chain Security & Intelligent Fuzzing

---

## 🤝 Contributing

Argus is open source and welcomes contributions!

- **[Contributing Guide](../.github/CONTRIBUTING.md)** - How to contribute code, docs, or ideas
- **[Development Setup](../.github/CONTRIBUTING.md#development-setup)** - Set up your dev environment
- **[Testing Guidelines](../.github/CONTRIBUTING.md#testing)** - Write and run tests
- **[Pull Request Process](../.github/CONTRIBUTING.md#pull-requests)** - How to submit PRs

---

## 📄 License & Legal

- **License:** MIT - see [LICENSE](../LICENSE)
- **Security Policy:** [SECURITY.md](../SECURITY.md)
- **Privacy:** No telemetry, no data collection

---

## 🆘 Support

### Get Help

- **Documentation:** You're here!
- **FAQ:** [Frequently Asked Questions](FAQ.md)
- **GitHub Issues:** [Report bugs](https://github.com/devatsecure/Argus-Security/issues)
- **GitHub Discussions:** [Ask questions](https://github.com/devatsecure/Argus-Security/discussions)

### Enterprise Support

For commercial support, SLA, custom integrations, or consulting:

- **Email:** enterprise@argus.io
- **Enterprise Docs:** [PLATFORM.md](../PLATFORM.md)

---

## 🔗 Quick Links

### Documentation
- [README](../README.md) - Main documentation
- [CLAUDE.md](../CLAUDE.md) - AI agent context (for development)
- [PLATFORM.md](../PLATFORM.md) - Platform deployment guide

### Code
- [GitHub Repository](https://github.com/devatsecure/Argus-Security)
- [GitHub Releases](https://github.com/devatsecure/Argus-Security/releases)
- [Docker Images](https://github.com/devatsecure/Argus-Security/pkgs/container/argus-action)

### Community
- [GitHub Discussions](https://github.com/devatsecure/Argus-Security/discussions)
- [Issue Tracker](https://github.com/devatsecure/Argus-Security/issues)
- [Pull Requests](https://github.com/devatsecure/Argus-Security/pulls)

---

<div align="center">

**Built by security engineers, for security engineers.** 🛡️

*Making security scanning intelligent, observable, and self-improving.*

[⭐ Star on GitHub](https://github.com/devatsecure/Argus-Security) | [📖 Read the Docs](#) | [💬 Join Discussions](https://github.com/devatsecure/Argus-Security/discussions)

</div>
