# Spontaneous Security Discovery Guide

## Overview

The Spontaneous Discovery system is an AI-powered security analysis engine that finds issues beyond traditional scanner detection rules. Inspired by Slack's proactive agent systems, it identifies architectural risks, hidden vulnerabilities, configuration problems, and data security issues through intelligent code analysis.

## Key Features

### 🎯 Discovery Categories

#### 1. Architecture Risks
- **Missing Authentication**: Detects API endpoints without authentication mechanisms
- **Missing Authorization**: Identifies lack of fine-grained access controls
- **Weak Cryptography**: Finds usage of MD5, SHA1, DES, RC4, ECB mode
- **Missing Input Validation**: Spots routes without validation layers

#### 2. Hidden Vulnerabilities
- **Missing Security Headers**: Identifies lack of HSTS, CSP, X-Frame-Options, etc.
- **Race Conditions**: (Future) Detects concurrent access issues
- **Business Logic Flaws**: (Future) Finds logic vulnerabilities
- **Insecure Defaults**: (Future) Configuration weaknesses

#### 3. Configuration Issues
- **CORS Misconfiguration**: Detects overly permissive `Access-Control-Allow-Origin: *`
- **Debug Mode Enabled**: Finds `DEBUG=True` in configuration files
- **Exposed Admin Interfaces**: Identifies admin routes without authentication
- **Weak IAM Policies**: (Future) Permission analysis

#### 4. Data Security
- **Sensitive Data in Logs**: Detects logging of passwords, tokens, API keys
- **PII Exposure**: (Future) Identifies exposed personal information
- **Insecure Storage**: (Future) Database security analysis
- **Missing Encryption**: (Future) Encryption at rest checks

### ✨ Key Differentiators

- **High Confidence Threshold**: Only returns findings with >0.7 confidence to minimize noise
- **Evidence-Based**: Provides specific file paths and code patterns supporting each finding
- **CWE Mappings**: Maps discoveries to Common Weakness Enumeration for standardization
- **Deduplication**: Avoids reporting issues already found by traditional scanners
- **Actionable Remediation**: Provides specific steps to fix each issue

## Installation

The spontaneous discovery system is included in Argus and requires no additional dependencies:

```bash
# Already available if you have Argus installed
pip install -r requirements.txt
```

## Usage

### CLI Usage

Run spontaneous discovery on a project:

```bash
# Basic usage
python scripts/spontaneous_discovery.py /path/to/project

# Specify architecture type
python scripts/spontaneous_discovery.py /path/to/project --architecture backend-api

# Limit files analyzed (performance)
python scripts/spontaneous_discovery.py /path/to/project --max-files 100

# Export results as JSON
python scripts/spontaneous_discovery.py /path/to/project --output findings.json
```

**Architecture Types:**
- `backend-api` - REST APIs, GraphQL servers, backend services
- `frontend` - React, Vue, Angular applications
- `web-app` - Full-stack web applications
- `microservice` - Individual microservices
- `mobile-backend` - Mobile API backends
- `iot` - IoT device firmware/software

### Programmatic Usage

```python
from spontaneous_discovery import SpontaneousDiscovery
from pathlib import Path

# Initialize discovery engine
discovery = SpontaneousDiscovery(llm_manager=None)

# Gather files to analyze
files = [str(f) for f in Path("./src").rglob("*.py")]

# Run discovery
discoveries = discovery.discover(
    files=files,
    existing_findings=[],  # From other scanners
    architecture="backend-api",
    max_files_analyze=50
)

# Process results
for d in discoveries:
    print(f"[{d.severity.upper()}] {d.title}")
    print(f"Confidence: {d.confidence:.0%}")
    print(f"Files affected: {len(d.affected_files)}")
    print(f"Remediation: {d.remediation}\n")
```

### Integration with HybridSecurityAnalyzer

Add spontaneous discovery to your hybrid security workflow:

```python
from hybrid_analyzer import HybridSecurityAnalyzer
from spontaneous_discovery import SpontaneousDiscovery

# Initialize analyzer with spontaneous discovery
analyzer = HybridSecurityAnalyzer(
    enable_semgrep=True,
    enable_trivy=True,
    enable_ai_enrichment=True,
    ai_provider="anthropic"
)

# Add spontaneous discovery
discovery_engine = SpontaneousDiscovery(
    llm_manager=analyzer.llm_manager
)

# Run full scan
result = analyzer.scan(
    target_path="/path/to/project",
    project_type="backend-api"
)

# Add spontaneous discoveries
discoveries = discovery_engine.discover(
    files=result.scanned_files,
    existing_findings=result.findings,
    architecture="backend-api"
)

# Convert to unified format and combine
for discovery in discoveries:
    finding = discovery.to_finding(
        repo="my-project",
        commit_sha="abc123",
        branch="main"
    )
    result.findings.append(finding)
```

### GitHub Actions Integration

Use in your CI/CD pipeline:

```yaml
name: Security Scan with Spontaneous Discovery

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Security Audit
        uses: devatsecure/Argus-Security@v1
        with:
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
          review-type: security
          enable-spontaneous-discovery: true
          fail-on-blockers: true

      - name: Upload Results
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: argus-findings.sarif
```

## Discovery Algorithm

The spontaneous discovery system works in several phases:

### Phase 1: File Pattern Analysis
- Analyzes project structure to understand architecture
- Identifies frameworks (Django, Flask, FastAPI, Express, etc.)
- Detects presence of auth, middleware, config files
- Maps routes, models, controllers

### Phase 2: Category-Specific Analysis
- **Architecture**: Checks for missing security layers
- **Hidden Vulns**: Looks for race conditions, logic flaws
- **Config**: Examines configuration files for issues
- **Data Security**: Analyzes data handling patterns

### Phase 3: Confidence Scoring
- Assigns confidence scores based on evidence strength
- Only returns findings with confidence > 0.7
- Factors in number of affected files, pattern clarity

### Phase 4: Deduplication
- Compares with existing scanner findings
- Removes overlapping CWEs and similar titles
- Ensures no duplicate reporting

## Output Format

### Discovery Object

```python
@dataclass
class Discovery:
    category: str           # "architecture", "hidden_vuln", "config", "data_security"
    title: str             # Human-readable title
    description: str       # Detailed description
    confidence: float      # 0.0-1.0 (only >0.7 returned)
    severity: str          # "critical", "high", "medium", "low"
    evidence: List[str]    # Supporting evidence
    remediation: str       # How to fix
    cwe_id: Optional[str]  # CWE mapping
    affected_files: List[str]
    references: List[str]  # OWASP, documentation links
```

### Example Output

```json
{
  "title": "Missing Authentication Layer",
  "category": "architecture",
  "severity": "high",
  "confidence": 0.75,
  "description": "The project appears to have API routes/endpoints but no clear authentication mechanism detected...",
  "evidence": [
    "Found 15 route files but no authentication modules",
    "No files containing 'auth', 'login', 'jwt', or 'oauth' detected"
  ],
  "remediation": "Implement authentication for all sensitive endpoints:\n1. Add authentication middleware...",
  "cwe_id": "CWE-306",
  "affected_files": [
    "app/routes.py",
    "api/endpoints.py"
  ]
}
```

## Performance Considerations

### File Limits
- Default: 50 files analyzed
- Configurable via `--max-files` or `max_files_analyze` parameter
- Analyzes most critical files first (routes, configs, models)

### Runtime
- Typical: 5-15 seconds for 50 files
- Scales linearly with file count
- No external API calls required (unless using LLM enrichment)

### Memory
- Minimal memory footprint (~50MB for 50 files)
- Reads files sequentially to avoid memory pressure

## Best Practices

### 1. Run After Traditional Scanners
Always run spontaneous discovery after Semgrep, Trivy, etc. to avoid duplicates:

```python
# 1. Run traditional scanners
semgrep_findings = run_semgrep()
trivy_findings = run_trivy()

# 2. Run spontaneous discovery with existing findings
discoveries = discovery_engine.discover(
    files=files,
    existing_findings=semgrep_findings + trivy_findings,  # Dedupe
    architecture="backend-api"
)
```

### 2. Tune Architecture Type
Specify the correct architecture for better accuracy:

```python
# Backend API - checks for auth, authorization, API security
discoveries = discovery.discover(files, [], "backend-api")

# Frontend - checks for XSS, CSP, CORS
discoveries = discovery.discover(files, [], "frontend")

# Microservice - checks for service-to-service auth
discoveries = discovery.discover(files, [], "microservice")
```

### 3. Adjust File Limits
Balance speed vs coverage:

```python
# Fast scan (CI/CD)
discoveries = discovery.discover(files, [], "backend-api", max_files_analyze=30)

# Thorough scan (weekly)
discoveries = discovery.discover(files, [], "backend-api", max_files_analyze=100)

# Complete scan (release)
discoveries = discovery.discover(files, [], "backend-api", max_files_analyze=500)
```

### 4. Review High-Confidence Findings First
Prioritize by confidence:

```python
sorted_discoveries = sorted(
    discoveries,
    key=lambda x: (x.confidence, x.severity),
    reverse=True
)

for d in sorted_discoveries:
    if d.confidence > 0.85:
        print(f"HIGH CONFIDENCE: {d.title}")
```

### 5. Track False Positives
Use the feedback system to improve accuracy:

```python
# Mark false positives
from feedback_collector import FeedbackCollector

feedback = FeedbackCollector()
feedback.record_feedback(
    finding_id=discovery.id,
    feedback_type="false_positive",
    reason="Test file, not production code"
)

# Future scans will learn from this feedback
```

## Extending the System

### Adding New Discovery Patterns

1. **Add CWE Mapping** in `SpontaneousDiscovery.CWE_MAPPINGS`:

```python
CWE_MAPPINGS = {
    "my_new_pattern": "CWE-XXX",
    # ...
}
```

2. **Create Detection Method**:

```python
def _check_my_pattern(self, files: List[str]) -> Optional[Discovery]:
    """Check for my new security pattern"""

    # 1. Analyze files
    issues_found = []
    for file_path in files:
        # ... pattern detection logic ...
        if pattern_matches:
            issues_found.append(file_path)

    # 2. Return discovery if found
    if issues_found:
        return Discovery(
            category="architecture",  # or "hidden_vuln", "config", "data_security"
            title="My New Security Issue",
            description="...",
            confidence=0.75,  # Must be > 0.7 to be returned
            severity="high",
            evidence=[f"{f}: reason" for f in issues_found],
            remediation="1. Do this\n2. Then this...",
            cwe_id=self.CWE_MAPPINGS["my_new_pattern"],
            affected_files=issues_found
        )

    return None
```

3. **Add to Discovery Method**:

```python
def analyze_architecture(self, files: List[str], architecture: str) -> List[Discovery]:
    discoveries = []

    # ... existing checks ...

    # Add your new check
    my_discovery = self._check_my_pattern(files)
    if my_discovery:
        discoveries.append(my_discovery)

    return discoveries
```

### Using AI for Enhanced Discovery

Integrate with LLMManager for AI-powered analysis:

```python
from orchestrator.llm_manager import LLMManager

# Initialize with AI
config = {
    "anthropic_api_key": os.getenv("ANTHROPIC_API_KEY"),
    "ai_provider": "anthropic"
}

llm_manager = LLMManager(config)
llm_manager.initialize()

# Use AI in discovery
discovery = SpontaneousDiscovery(llm_manager=llm_manager)

# Now discovery methods can use AI for deeper analysis
```

## Troubleshooting

### No Discoveries Found

**Possible causes:**
1. Confidence threshold too high (all findings < 0.7)
2. Files already covered by traditional scanners
3. Project architecture not matching selected type

**Solutions:**
```python
# Temporarily lower threshold for debugging
discoveries = [d for d in all_discoveries if d.confidence > 0.5]

# Check what was found before filtering
print(f"Total discoveries (all confidence): {len(all_discoveries)}")
print(f"High confidence (>0.7): {len(high_confidence)}")
```

### Too Many False Positives

**Tuning confidence thresholds:**
```python
# Increase threshold for specific categories
high_precision_discoveries = [
    d for d in discoveries
    if d.confidence > 0.85  # Stricter
    or d.category == "data_security"  # Always include data issues
]
```

### Performance Issues

**Optimization strategies:**
```python
# 1. Reduce file limit
discoveries = discovery.discover(files[:30], [], "backend-api")

# 2. Filter files by extension/path
critical_files = [f for f in files if "routes" in f or "api" in f]
discoveries = discovery.discover(critical_files, [], "backend-api")

# 3. Skip test files
prod_files = [f for f in files if "test" not in f.lower()]
```

## Comparison with Traditional Scanners

| Feature | Traditional Scanners | Spontaneous Discovery |
|---------|---------------------|----------------------|
| **Detection Method** | Rule-based patterns | Architectural analysis |
| **Coverage** | Known vulnerabilities | Missing controls, design flaws |
| **False Positives** | 5-30% | <10% (high confidence only) |
| **Speed** | Fast (seconds) | Fast (seconds) |
| **Customization** | Rule configuration | AI-powered context |
| **Best For** | Known CVEs, common bugs | Design issues, missing features |

## Examples

### Example 1: Detecting Missing Authentication

```bash
$ python scripts/spontaneous_discovery.py ./my-api --architecture backend-api

Found 45 files to analyze
🔍 Starting spontaneous discovery
   📁 Analyzing 45 files
   🏗️  Architecture: backend-api
   🏛️  Analyzing architecture risks...
      Found 1 architecture risks
   ✅ Spontaneous discovery complete: 1 high-confidence findings

[HIGH] Missing Authentication Layer
Confidence: 75%
The project appears to have API routes/endpoints but no clear
authentication mechanism detected. This could allow unauthorized
access to sensitive functionality.

Affected files:
  - app/routes.py
  - api/handlers.py

Remediation:
1. Add authentication middleware/decorators
2. Use JWT, OAuth2, or session-based auth
3. Protect all non-public routes
4. Implement proper session management
```

### Example 2: Finding Weak Cryptography

```bash
$ python scripts/spontaneous_discovery.py ./legacy-app

[MEDIUM] Weak Cryptographic Algorithms Detected
Confidence: 85%

Evidence:
  - utils/crypto.py: MD5 hash function (cryptographically broken)
  - auth/tokens.py: SHA1 hash function (deprecated for security)
  - db/encryption.py: DES encryption (insecure, use AES)

Remediation:
1. Use SHA-256 or SHA-3 instead of MD5/SHA1 for hashing
2. Use AES-256-GCM instead of DES/RC4 for encryption
3. Avoid ECB mode, use GCM or CBC with proper IV
4. Use bcrypt/argon2 for password hashing
```

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE/SANS Top 25](https://cwe.mitre.org/top25/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [Argus Documentation](../README.md)

## Support

For issues or questions:
- GitHub Issues: https://github.com/devatsecure/Argus-Security/issues
- Documentation: https://github.com/devatsecure/Argus-Security/docs

## License

MIT License - See LICENSE file for details
