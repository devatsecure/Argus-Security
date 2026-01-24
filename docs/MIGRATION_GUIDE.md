# Migration Guide: New Security Feature Inputs

## Overview

Argus v1.0.16+ now exposes all 10 security features directly in GitHub Action inputs, making them discoverable and configurable without CLI knowledge.

## What Changed

### Before (v1.0.15 and earlier)

```yaml
- uses: devatsecure/Argus-Security@v1
  with:
    anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
    # Only 3 security features exposed:
    # - semgrep-enabled
    # - enable-exploit-analysis
    # - generate-security-tests
    # Other features required CLI/SDK knowledge
```

### After (v1.0.16+)

```yaml
- uses: devatsecure/Argus-Security@v1
  with:
    anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}

    # Now all 10 security features are exposed:
    enable-api-security: 'true'           # NEW
    enable-dast: 'false'                  # NEW
    dast-target-url: ''                   # NEW
    enable-supply-chain: 'true'           # NEW
    enable-fuzzing: 'false'               # NEW
    fuzzing-duration: '300'               # NEW
    enable-threat-intel: 'true'           # NEW
    enable-remediation: 'true'            # NEW
    enable-runtime-security: 'false'      # NEW
    runtime-monitoring-duration: '60'     # NEW
    enable-regression-testing: 'true'     # NEW
```

## New Feature Inputs

| Input Name | Type | Default | Description |
|------------|------|---------|-------------|
| `enable-api-security` | boolean | `true` | OWASP API Top 10 testing (REST/GraphQL/gRPC) |
| `enable-dast` | boolean | `false` | Dynamic application security testing with Nuclei |
| `dast-target-url` | string | `''` | Target URL for DAST scanning |
| `enable-supply-chain` | boolean | `true` | Supply chain attack detection (typosquatting, malicious packages) |
| `enable-fuzzing` | boolean | `false` | AI-guided fuzzing with 60+ payloads |
| `fuzzing-duration` | integer | `300` | Fuzzing duration in seconds |
| `enable-threat-intel` | boolean | `true` | Threat intelligence enrichment (CISA KEV, EPSS, NVD) |
| `enable-remediation` | boolean | `true` | AI-powered vulnerability fix generation |
| `enable-runtime-security` | boolean | `false` | Container runtime security monitoring with Falco |
| `runtime-monitoring-duration` | integer | `60` | Runtime monitoring duration in seconds |
| `enable-regression-testing` | boolean | `true` | Security regression test generation |

## Migration Steps

### Step 1: Check Your Current Configuration

If you're using the default configuration:
```yaml
- uses: devatsecure/Argus-Security@v1
  with:
    anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
```

**No changes required!** All new features with `default: 'true'` are automatically enabled.

### Step 2: Opt Into Optional Features

If you want to enable DAST, fuzzing, or runtime security:

```yaml
- uses: devatsecure/Argus-Security@v1
  with:
    anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}

    # Enable DAST for staging environment
    enable-dast: 'true'
    dast-target-url: 'https://staging.example.com'

    # Enable fuzzing for 5 minutes
    enable-fuzzing: 'true'
    fuzzing-duration: '300'

    # Enable runtime monitoring for 2 minutes
    enable-runtime-security: 'true'
    runtime-monitoring-duration: '120'
```

### Step 3: Disable Unwanted Features

If you want to reduce scan time or cost:

```yaml
- uses: devatsecure/Argus-Security@v1
  with:
    anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}

    # Disable expensive features
    enable-api-security: 'false'
    enable-threat-intel: 'false'
    enable-remediation: 'false'
```

## Backward Compatibility

✅ **All existing workflows continue to work without changes.**

- Default values match previous behavior
- Previously exposed features (`semgrep-enabled`, `enable-exploit-analysis`, `generate-security-tests`) work as before
- New features are opt-in (disabled by default for resource-intensive ones)

## Cost Impact

### Default Configuration (No Changes)

| Feature | Enabled by Default | Cost Impact |
|---------|-------------------|-------------|
| API Security | ✅ Yes | +$0.05-0.10/scan |
| Supply Chain | ✅ Yes | +$0.02-0.05/scan |
| Threat Intel | ✅ Yes | +$0.03-0.05/scan |
| Remediation | ✅ Yes | +$0.10-0.15/scan |
| Regression Testing | ✅ Yes | +$0.02-0.05/scan |
| **Total** | - | **+$0.22-0.40/scan** |

**Previous cost:** ~$0.35/scan
**New cost:** ~$0.57-0.75/scan
**Increase:** ~$0.22-0.40/scan (63% increase)

### Opt-In Features (Disabled by Default)

| Feature | Enabled by Default | Cost Impact |
|---------|-------------------|-------------|
| DAST | ❌ No | +$0.15-0.30/scan |
| Fuzzing | ❌ No | +$0.20-0.40/scan |
| Runtime Security | ❌ No | +$0.10-0.20/scan |

### Cost Reduction Strategy

If the cost increase is too high, disable features you don't need:

```yaml
- uses: devatsecure/Argus-Security@v1
  with:
    anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}

    # Keep cost at ~$0.35/scan (original level)
    enable-api-security: 'false'
    enable-supply-chain: 'false'
    enable-threat-intel: 'false'
    enable-remediation: 'false'
    enable-regression-testing: 'false'
```

Or use Ollama for $0.00 cost:

```yaml
- uses: devatsecure/Argus-Security@v1
  with:
    ai-provider: 'ollama'
    ollama-endpoint: 'http://localhost:11434'
    # All features enabled, $0.00 cost!
```

## Examples

### Minimal Configuration (Cost-Optimized)

```yaml
name: Security Scan (Minimal)
on: [pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: devatsecure/Argus-Security@v1
        with:
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
          only-changed: 'true'

          # Disable expensive features
          enable-api-security: 'false'
          enable-supply-chain: 'false'
          enable-threat-intel: 'false'
          enable-remediation: 'false'
          enable-regression-testing: 'false'
```

Cost: ~$0.35/scan (original)

### Balanced Configuration (Recommended)

```yaml
name: Security Scan (Balanced)
on: [pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: devatsecure/Argus-Security@v1
        with:
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
          only-changed: 'true'

          # Keep essential features
          enable-api-security: 'true'
          enable-supply-chain: 'true'
          enable-threat-intel: 'true'
          enable-remediation: 'false'       # Disable for cost savings
          enable-regression-testing: 'true'
```

Cost: ~$0.45-0.60/scan (moderate increase)

### Maximum Security Configuration

```yaml
name: Security Scan (Max)
on: [pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: devatsecure/Argus-Security@v1
        with:
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}

          # Enable ALL features
          enable-api-security: 'true'
          enable-supply-chain: 'true'
          enable-threat-intel: 'true'
          enable-remediation: 'true'
          enable-regression-testing: 'true'

          # Enable optional features
          enable-dast: 'true'
          dast-target-url: 'https://staging.example.com'

          enable-fuzzing: 'true'
          fuzzing-duration: '300'

          enable-runtime-security: 'true'
          runtime-monitoring-duration: '60'
```

Cost: ~$1.00-1.50/scan (maximum coverage)

## Troubleshooting

### "DAST scan failed: no target URL"

**Cause:** DAST enabled but no target URL provided.

**Fix:**
```yaml
enable-dast: 'true'
dast-target-url: 'https://staging.example.com'  # Required!
```

### "Runtime security requires Docker"

**Cause:** Runtime security enabled but Docker not available.

**Fix:** Ensure GitHub Actions runner has Docker access, or disable:
```yaml
enable-runtime-security: 'false'
```

### "Cost limit exceeded"

**Cause:** Too many features enabled for large repos.

**Fix:** Disable expensive features or increase cost limit:
```yaml
cost-limit: '2.0'  # Increase from default $1.00
```

Or disable features:
```yaml
enable-fuzzing: 'false'
enable-dast: 'false'
```

## FAQ

**Q: Will my existing workflows break?**
A: No, all existing workflows continue to work without changes. New features are additive.

**Q: What if I don't want the new features?**
A: Set them to `'false'` explicitly. Default configuration is balanced for typical use.

**Q: How do I know which features to enable?**
A: Start with defaults, then:
- **API-heavy projects**: Keep `enable-api-security: 'true'`
- **Dependency-heavy projects**: Keep `enable-supply-chain: 'true'`
- **Staging environment available**: Enable `enable-dast: 'true'`
- **Performance-critical**: Enable `enable-fuzzing: 'true'`
- **Container deployments**: Enable `enable-runtime-security: 'true'`

**Q: Can I use CLI instead of GitHub Action inputs?**
A: Yes! CLI still works. See `scripts/argus --help`.

## Support

- **Issues**: [GitHub Issues](https://github.com/devatsecure/Argus-Security/issues)
- **Discussions**: [GitHub Discussions](https://github.com/devatsecure/Argus-Security/discussions)
- **Documentation**: [docs/index.md](docs/index.md)

---

**Migration Date:** 2026-01-16
**Version:** v1.0.16+
