# Security Policy

## Supported Versions

We release patches for security vulnerabilities. Currently supported versions:

| Version | Supported          |
| ------- | ------------------ |
| 1.1.x   | :white_check_mark: |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take the security of Argus seriously. If you believe you have found a security vulnerability, please report it to us as described below.

### Where to Report

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to: **security@devatsecure.com**

### What to Include

Please include the following information in your report:

- Type of issue (e.g., buffer overflow, SQL injection, cross-site scripting, etc.)
- Full paths of source file(s) related to the manifestation of the issue
- The location of the affected source code (tag/branch/commit or direct URL)
- Any special configuration required to reproduce the issue
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue, including how an attacker might exploit it

### What to Expect

- **Acknowledgment**: We will acknowledge receipt of your vulnerability report within 48 hours.
- **Updates**: We will send you regular updates about our progress, at minimum every 7 days.
- **Verification**: We will work to verify the vulnerability and determine its impact.
- **Fix**: We will work on a fix and coordinate the release with you.
- **Disclosure**: We prefer coordinated disclosure and will work with you on timing.

### Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Fix Timeline**: Depends on severity
  - Critical: 7 days
  - High: 14 days
  - Medium: 30 days
  - Low: 90 days

## Security Measures

Argus implements several security measures:

### Code Security

- **Static Analysis**: Semgrep, CodeQL, and Bandit scans
- **Dependency Scanning**: Trivy and Dependabot
- **Secret Scanning**: TruffleHog and Gitleaks
- **IaC Security**: Checkov for infrastructure code
- **SBOM**: Software Bill of Materials generation
- **Signing**: Cosign artifact signing

### Development Security

- **Branch Protection**: Required reviews on main and develop
- **Signed Commits**: GPG signing recommended
- **CI/CD Security**: Minimal permissions, pinned actions
- **Code Review**: All changes reviewed before merge

### Runtime Security

- **Least Privilege**: Minimal permissions for all operations
- **Input Validation**: All user inputs validated
- **Secure Defaults**: Security-first configuration
- **Audit Logging**: Comprehensive activity logging

## Security Best Practices for Users

### API Keys

- Never commit API keys to the repository
- Use environment variables or secret management
- Rotate keys regularly
- Use minimal scope for API keys

### Deployment

- Run with minimal required permissions
- Use read-only file systems where possible
- Enable audit logging
- Keep dependencies updated

### Configuration

- Review and customize security policies
- Set appropriate thresholds for findings
- Configure alert notifications
- Enable all relevant scanners

## Known Security Considerations

### AI Model Usage

Argus integrates with AI models (Claude, Foundation-Sec). Be aware:

- AI responses are sent to third-party APIs
- Code snippets may be transmitted for analysis
- Use self-hosted models (Foundation-Sec) for sensitive code
- Review privacy policies of AI providers

### Network Access

- Some scanners require network access
- SBOM generation may download package metadata
- Consider using in air-gapped environments with local mirrors

### Permissions

- GitHub Actions require specific permissions
- Review and minimize token scopes
- Use GITHUB_TOKEN with minimal permissions

## Security Updates

We publish security advisories for:

- Critical vulnerabilities in Argus
- High-severity dependency vulnerabilities
- Security-related configuration changes

Subscribe to security advisories:
- Watch this repository for security alerts
- Enable Dependabot alerts
- Follow releases for security updates

## Compliance

Argus supports compliance requirements:

- **SOC 2**: Automated compliance checks
- **SLSA**: Supply chain security (Level 2)
- **SBOM**: CycloneDX format
- **Provenance**: Signed attestations

## Security Scanning Results

Our security posture:

- **Semgrep**: Continuous SAST scanning
- **CodeQL**: GitHub Advanced Security
- **Trivy**: Dependency vulnerability scanning
- **OpenSSF Scorecard**: Security best practices
- **Gitleaks**: Secret detection

View current security status:
- [Security Tab](https://github.com/devatsecure/Argus-Security/security)
- [Code Scanning](https://github.com/devatsecure/Argus-Security/security/code-scanning)
- [Dependabot Alerts](https://github.com/devatsecure/Argus-Security/security/dependabot)

## Attribution

We believe in responsible disclosure and will credit security researchers who report vulnerabilities to us (unless you prefer to remain anonymous).

## Questions?

If you have questions about this security policy, please contact: security@devatsecure.com

---

**Last Updated**: January 29, 2026  
**Version**: 1.1

