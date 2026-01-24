---
title: Scanner Reference
sidebar_position: 1
ai_generated: true
last_updated: 2024-11-10
---

> ⚠️ **AI-Generated Documentation** - Please review and validate

# Scanner Reference

Complete reference for all 4 security scanners orchestrated by Argus.

## Scanner Overview

| Scanner | Type | Purpose | Strength | Speed | False Positive Rate |
|---------|------|---------|----------|-------|---------------------|
| **Semgrep** | SAST | Static code analysis (2000+ rules) | Language-aware | Fast | Low (~10%) |
| **Trivy** | Dependency Scan | CVE detection in dependencies | Comprehensive DB | Fast | Medium (~25%) |
| **TruffleHog** | Secret Detection | Verified secrets via API validation | High precision | Fast | Very Low (~5%) |
| **Checkov** | IaC Security | Infrastructure misconfigurations | Cloud-native | Fast | Medium (~20%) |

## Semgrep

### What It Does
Static analysis (SAST) using **2000+ rules** to detect code vulnerabilities, anti-patterns, and security issues.

### Key Features
- **Language-Aware**: Understands code semantics
- **Fast**: Analyzes code without compilation
- **Low False Positives**: Precise pattern matching
- **Custom Rules**: Write your own rules
- **OWASP Coverage**: Detects OWASP Top 10

### What It Finds
- SQL injection
- XSS vulnerabilities
- Command injection
- Path traversal
- Insecure crypto
- Authentication issues
- Authorization bypasses
- 2000+ security patterns

### Supported Languages
Python, JavaScript, TypeScript, Java, Go, Ruby, PHP, C#, Kotlin, Scala, Rust, Swift, Terraform

### Configuration

```yaml
- uses: devatsecure/Argus-Security@v3
  with:
    semgrep-rules: 'p/security-audit,p/owasp-top-ten'
    semgrep-config: '.semgrep.yml'  # Custom rules
```

### Example Finding

```json
{
  "scanner": "semgrep",
  "rule": "python.lang.security.audit.sqli.sql-injection",
  "file": "app/models/user.py",
  "line": 156,
  "severity": "high",
  "message": "User input directly concatenated into SQL query",
  "fix": "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))"
}
```

### When to Use
- ✅ Always enable (default)
- ✅ Best SAST tool for modern languages
- ✅ Low false positives (~10%)

## TruffleHog

### What It Does
Detects secrets (API keys, tokens, credentials) and **verifies them** by calling the actual service APIs to confirm they're valid.

### Key Features
- **Verified Detection**: Calls APIs to confirm secrets are real
- **Git History Scanning**: Finds secrets in commit history
- **Entropy Detection**: Identifies high-entropy strings
- **Custom Patterns**: Supports custom regex patterns

### What It Finds
- AWS access keys (verified via AWS API)
- GitHub tokens (verified via GitHub API)
- Stripe API keys (verified via Stripe API)
- Database credentials
- Private keys (SSH, PGP)
- 700+ secret types

### Configuration

```yaml
- uses: devatsecure/Argus-Security@v3
  with:
    # TruffleHog is enabled by default
    trufflehog-verify: 'true'  # Enable API verification
    trufflehog-since: '1 week ago'  # Scan recent commits
```

### Example Finding

```json
{
  "scanner": "trufflehog",
  "type": "AWS Access Key",
  "file": "config/aws.yml",
  "line": 12,
  "verified": true,
  "severity": "critical",
  "message": "AWS access key verified via API - immediate rotation required"
}
```

### When to Use
- ✅ Always enable (default)
- ✅ Critical for preventing secret leaks
- ✅ Low false positive rate due to verification

## Trivy

### What It Does
Scans **dependencies, containers, and IaC** for known CVEs using comprehensive vulnerability databases.

### Key Features
- **Multi-Target**: Dependencies, containers, IaC, filesystems
- **Comprehensive DB**: NVD, GitHub Advisory, etc.
- **Fast**: Parallel scanning
- **SBOM Generation**: Creates Software Bill of Materials
- **Reachability Analysis**: Checks if vulnerable code is reachable

### What It Finds
- CVEs in dependencies (npm, pip, maven, go.mod, etc.)
- Container vulnerabilities (OS packages, app dependencies)
- IaC misconfigurations (Terraform, CloudFormation, Kubernetes)
- License issues
- Secrets in containers

### Supported Ecosystems
npm, pip, maven, gradle, go modules, cargo, composer, bundler, nuget, cocoapods

### Configuration

```yaml
- uses: devatsecure/Argus-Security@v3
  with:
    trivy-severity: 'CRITICAL,HIGH,MEDIUM'
    trivy-vuln-type: 'os,library'
    trivy-skip-dirs: 'node_modules,vendor'
```

### Example Finding

```json
{
  "scanner": "trivy",
  "cve": "CVE-2024-1234",
  "package": "requests",
  "installed_version": "2.25.1",
  "fixed_version": "2.31.0",
  "severity": "high",
  "cvss_score": 7.5,
  "message": "HTTP request smuggling vulnerability",
  "fix": "Upgrade to requests>=2.31.0"
}
```

### When to Use
- ✅ Always enable (default)
- ✅ Critical for dependency management
- ⚠️ Medium false positives (~25%) - many CVEs not exploitable

## Checkov

### What It Does
Scans **Infrastructure as Code** (Terraform, CloudFormation, Kubernetes, etc.) for security misconfigurations and compliance violations.

### Key Features
- **Multi-IaC**: Terraform, CloudFormation, Kubernetes, Helm, ARM, etc.
- **1000+ Policies**: CIS benchmarks, PCI-DSS, HIPAA, SOC 2
- **Custom Policies**: Python-based custom checks
- **Graph-Based**: Understands resource relationships
- **Fix Suggestions**: Provides remediation guidance

### What It Finds
- Public S3 buckets
- Unencrypted databases
- Overly permissive IAM policies
- Missing security groups
- Unencrypted traffic
- Compliance violations
- 1000+ IaC security issues

### Supported IaC
Terraform, CloudFormation, Kubernetes, Helm, ARM templates, Docker, Serverless

### Configuration

```yaml
- uses: devatsecure/Argus-Security@v3
  with:
    checkov-framework: 'terraform,kubernetes'
    checkov-skip-check: 'CKV_AWS_20,CKV_AWS_21'  # Skip specific checks
```

### Example Finding

```json
{
  "scanner": "checkov",
  "check": "CKV_AWS_18",
  "resource": "aws_s3_bucket.data",
  "file": "terraform/s3.tf",
  "line": 12,
  "severity": "high",
  "message": "S3 bucket does not have access logging enabled",
  "fix": "Add logging { target_bucket = aws_s3_bucket.logs.id }"
}
```

### When to Use
- ✅ Always enable if using IaC (default)
- ✅ Critical for cloud security
- ⚠️ Medium false positives (~20%) - some checks too strict

## Scanner Comparison

### When to Use Which Scanner

| Use Case | Recommended Scanners | Rationale |
|----------|---------------------|-----------|
| **Prevent Secret Leaks** | TruffleHog | Verified secret detection with API validation |
| **Find Code Vulnerabilities** | Semgrep | Best SAST for modern languages |
| **Track CVEs** | Trivy | Comprehensive vulnerability DB |
| **Secure Infrastructure** | Checkov | IaC security and compliance |
| **Fast PR Reviews** | All (default) | Parallel execution, <5 min |
| **Cost-Optimized** | All with Ollama | $0 API cost, good noise reduction |
| **High-Security Projects** | All with Claude + Aardvark | 95%+ accuracy, exploit analysis |

### Performance Comparison

| Scanner | Avg Runtime | Memory Usage | CPU Usage |
|---------|-------------|--------------|-----------|
| Semgrep | 60-120s | 500MB | Medium |
| Trivy | 30-60s | 300MB | Low |
| TruffleHog | 30-60s | 200MB | Low |
| Checkov | 20-40s | 200MB | Low |
| **Total (Parallel)** | **2-3 min** | **1.2GB** | **Medium** |

## Disabling Scanners

If you don't need a specific scanner:

```yaml
- uses: devatsecure/Argus-Security@v3
  with:
    disable-scanners: 'checkov,trivy'  # Disable IaC and dependency scanning
```

**When to disable**:
- No IaC → Disable Checkov
- No dependencies → Disable Trivy
- Secrets only → Disable Semgrep and Checkov
- Code analysis only → Disable TruffleHog and Checkov

## Related Documentation

- [Architecture Overview](../architecture/overview.md)
- [Best Practices Guide](../best-practices.md)
- [ADR-0002: Multi-Scanner Architecture](../adrs/0002-multi-scanner-architecture.md)


